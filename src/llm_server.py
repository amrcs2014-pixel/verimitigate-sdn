"""Batched, cached LLM inference server (Qwen2.5-1.5B-Instruct on a GTX 1060).

Simulation workers send chat messages over a local authenticated socket.  The server
batches concurrent requests (greedy decoding), caches every completion on disk, and
returns the text together with the *calibrated single-request latency* for that prompt
and output length on this GPU (see calibrate_latency()), which is what the closed loop
charges as synthesis time.
"""
import os, sys, json, time, threading, queue, hashlib, sqlite3
from multiprocessing.connection import Listener, Client

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADDR, KEY = ("127.0.0.1", 6011), b"verimitigate"
CACHE = os.path.join(ROOT, "results", "llm_cache.sqlite")
CALIB = os.path.join(ROOT, "results", "latency_calib.json")
MODEL = os.path.join(ROOT, "models", "qwen1.5b")


def key_of(msgs, max_new, tag):
    return hashlib.sha256(json.dumps([tag, msgs, max_new], sort_keys=True).encode()).hexdigest()


class Engine:
    def __init__(self, adapter=None):
        import torch, torch.nn as nn, torch.nn.functional as F
        from transformers import AutoTokenizer, AutoModelForCausalLM
        self.torch = torch
        self.tok = AutoTokenizer.from_pretrained(MODEL); self.tok.padding_side = "left"
        m = AutoModelForCausalLM.from_pretrained(MODEL, dtype=torch.float16).cuda().eval()

        # Pascal GPUs have very slow fp16 GEMM: run prefill (many tokens) in fp32 compute on
        # fp16-stored weights; decode (1 token/step) stays in native fp16.
        def fwd(self, x):
            if x.shape[-2] > 1:
                return F.linear(x.float(), self.weight.float(), None if self.bias is None else self.bias.float()).to(x.dtype)
            return F.linear(x, self.weight, self.bias)
        for mod in m.modules():
            if isinstance(mod, nn.Linear): mod.forward = fwd.__get__(mod)
        self.m = m
        self.tag = "qwen2.5-1.5b-instruct"
        self.adapters = {}
        self.merged = None
        if adapter and adapter.startswith("merge:"):
            # merge one LoRA adapter into the fp16 base weights: W <- W + s * B A (no per-token overhead)
            name, path = adapter[6:].split("=")
            sd = torch.load(path, map_location="cpu")
            mods = dict(m.named_modules())
            groups = {}
            for k, v in sd.items():
                mod_name, rest = k.split(".adapters.")
                groups.setdefault(mod_name, {})[rest[2:]] = v
            with torch.no_grad():
                for mod_name, ab in groups.items():
                    lin = mods[mod_name]
                    lin.weight += ((ab["B"].float() @ ab["A"].float()) * (32 / 16)).to(lin.weight.dtype).cuda()
            self.merged = name
            self.tag_merge = name
            adapter = None
        if adapter:
            import lora
            lora.inject(m, train_mode=False)
            for spec in adapter.split(","):
                name, path = spec.split("=")
                lora.register_adapter(m, path, name)
                self.adapters[name] = path
            self.lora = lora
        self.cur = None

    def activate(self, name):
        if self.merged is not None:
            if name != self.merged: raise ValueError(f"server has merged adapter {self.merged}, request wants {name}")
            return
        if name == self.cur: return
        if name and name not in self.adapters: raise ValueError("unknown adapter " + name)
        if self.adapters: self.lora.set_active(self.m, name or None)
        self.cur = name

    def encode(self, msgs):
        return self.tok.apply_chat_template(msgs, add_generation_prompt=True, tokenize=False)

    def generate_greedy_shrinking(self, batch_msgs, max_new):
        """Greedy decoding that drops finished sequences from the batch (and from the KV cache) at every
        step, so a batch costs the sum of its sequences' lengths rather than batch x longest."""
        torch = self.torch
        texts = [self.encode(m) for m in batch_msgs]
        enc = self.tok(texts, return_tensors="pt", padding=True).to("cuda")
        eos = {self.tok.eos_token_id, self.tok.convert_tokens_to_ids("<|im_end|>"), self.tok.pad_token_id}
        attn = enc.attention_mask
        pos = (attn.cumsum(-1) - 1).clamp(min=0)
        B = attn.shape[0]
        gens = [[] for _ in range(B)]
        with torch.no_grad():
            out = self.m(input_ids=enc.input_ids, attention_mask=attn, position_ids=pos, use_cache=True)
            past = out.past_key_values
            nxt = out.logits[:, -1].argmax(-1)
            alive = list(range(B))
            for step in range(max_new):
                keep = []
                for j, i in enumerate(alive):
                    t = int(nxt[j])
                    if t in eos: continue
                    gens[i].append(t)
                    if len(gens[i]) < max_new: keep.append(j)
                if not keep: break
                if len(keep) < len(alive):
                    idx = torch.tensor(keep, device="cuda")
                    past.batch_select_indices(idx)
                    attn = attn[idx]; nxt = nxt[idx]
                    alive = [alive[j] for j in keep]
                attn = torch.cat([attn, torch.ones_like(attn[:, :1])], dim=1)
                p = (attn.sum(-1, keepdim=True) - 1)
                out = self.m(input_ids=nxt[:, None], attention_mask=attn, position_ids=p, past_key_values=past, use_cache=True)
                past = out.past_key_values
                nxt = out.logits[:, -1].argmax(-1)
        res = []
        for i in range(B):
            res.append((self.tok.decode(gens[i], skip_special_tokens=True), int(enc.attention_mask[i].sum()), len(gens[i])))
        return res

    def generate(self, batch_msgs, max_new, adapter=None, temperature=0.0):
        if temperature <= 0 and getattr(self, "shrink", False):
            self.activate(adapter)
            return self.generate_greedy_shrinking(batch_msgs, max_new)
        torch = self.torch
        self.activate(adapter)
        texts = [self.encode(m) for m in batch_msgs]
        enc = self.tok(texts, return_tensors="pt", padding=True).to("cuda")
        with torch.no_grad():
            if temperature > 0:
                out = self.m.generate(**enc, max_new_tokens=max_new, do_sample=True, temperature=temperature,
                                      top_p=0.95, top_k=None, pad_token_id=self.tok.pad_token_id)
            else:
                out = self.m.generate(**enc, max_new_tokens=max_new, do_sample=False, temperature=None,
                                      top_p=None, top_k=None, pad_token_id=self.tok.pad_token_id)
        res = []
        L = enc.input_ids.shape[1]
        for i in range(len(texts)):
            gen = out[i, L:]
            gen = gen[gen != self.tok.pad_token_id]
            n_in = int(enc.attention_mask[i].sum())
            res.append((self.tok.decode(gen, skip_special_tokens=True), n_in, int(len(gen))))
        return res


def latency_model():
    c = json.load(open(CALIB))
    return lambda n_in, n_out: c["a"] + c["b"] * n_in + c["c"] * n_out


class Server:
    def __init__(self, bmax=16, wait=0.6, adapter=None):
        self.eng = Engine(adapter)
        self.q = queue.Queue()
        self.bmax, self.wait = bmax, wait
        self.db = sqlite3.connect(CACHE, check_same_thread=False)
        self.db.execute("create table if not exists c (k text primary key, text text, n_in int, n_out int)")
        self.lock = threading.Lock()
        self.lat = latency_model() if os.path.exists(CALIB) else (lambda a, b: 0.0)
        self.stats = dict(req=0, hit=0, gen=0, batches=0)
        self.tok_budget = int(os.environ.get("TOK_BUDGET", "9000"))

    def lookup(self, k):
        with self.lock:
            r = self.db.execute("select text, n_in, n_out from c where k=?", (k,)).fetchone()
        return r

    def store(self, k, text, n_in, n_out):
        with self.lock:
            self.db.execute("insert or replace into c values (?,?,?,?)", (k, text, n_in, n_out)); self.db.commit()

    def handle_conn(self, conn):
        try:
            while True:
                req = conn.recv()
                if req == "stats": conn.send(self.stats); continue
                msgs, max_new = req["msgs"], req.get("max_new", 160)
                ad = req.get("adapter") or ""
                if self.eng.merged is not None and ad != self.eng.merged or (self.eng.merged is None and not self.eng.adapters and ad):
                    conn.send(dict(error=f"adapter mismatch: server={self.eng.merged}, request={ad}")); continue
                temp = float(req.get("temperature", 0.0)); sid = req.get("sample_id", 0)
                k = key_of(msgs, max_new, self.eng.tag + ":" + ad + (f":T{temp}:{sid}" if temp > 0 else ""))
                self.stats["req"] += 1
                r = self.lookup(k)
                if r is None:
                    ev = threading.Event(); slot = {}
                    self.q.put((msgs, (max_new, ad, temp), k, ev, slot)); ev.wait()
                    r = slot["r"]
                else:
                    self.stats["hit"] += 1
                text, n_in, n_out = r
                conn.send(dict(text=text, n_in=n_in, n_out=n_out, latency=self.lat(n_in, n_out)))
        except (EOFError, ConnectionResetError, OSError):
            pass

    def batcher(self):
        while True:
            items = [self.q.get()]
            t0 = time.time()
            while len(items) < self.bmax and time.time() - t0 < self.wait:
                try: items.append(self.q.get(timeout=0.05))
                except queue.Empty: pass
            by_len = {}
            for it in items: by_len.setdefault(it[1], []).append(it)
            for (max_new, ad, temp), grp in by_len.items():
                # token budget per batch: sort by prompt length and chunk
                grp.sort(key=lambda g: len(json.dumps(g[0])))
                chunks, cur, budget = [], [], 0
                for g in grp:
                    L = len(json.dumps(g[0])) // 3 + max_new
                    if cur and (budget + L > self.tok_budget):
                        chunks.append(cur); cur, budget = [], 0
                    cur.append(g); budget += L
                if cur: chunks.append(cur)
                for ch in chunks:
                    self.run_chunk(ch, max_new, ad, temp)

    def run_chunk(self, ch, max_new, ad, temp):
        try:
            outs = self.eng.generate([g[0] for g in ch], max_new, ad or None, temp)
        except Exception as e:
            self.eng.torch.cuda.empty_cache()
            if len(ch) > 1:
                h = len(ch) // 2
                self.run_chunk(ch[:h], max_new, ad, temp); self.run_chunk(ch[h:], max_new, ad, temp)
                return
            print("generation failed:", repr(e)[:300], flush=True)
            outs = [("", 0, 0)]
        self.stats["gen"] += len(ch); self.stats["batches"] += 1
        for g, o in zip(ch, outs):
            if o[2] > 0: self.store(g[2], *o)
            g[4]["r"] = o; g[3].set()

    def serve(self):
        threading.Thread(target=self.batcher, daemon=True).start()
        lst = Listener(ADDR, authkey=KEY)
        print("LLM server ready", flush=True)
        while True:
            c = lst.accept()
            threading.Thread(target=self.handle_conn, args=(c,), daemon=True).start()


class LLMClient:
    def __init__(self, adapter=None):
        self.c, self.adapter = None, adapter

    def __call__(self, msgs, max_new=160, temperature=0.0, sample_id=0):
        for attempt in range(600):
            try:
                if self.c is None: self.c = Client(ADDR, authkey=KEY)
                self.c.send(dict(msgs=msgs, max_new=max_new, adapter=self.adapter, temperature=temperature,
                                 sample_id=sample_id))
                r = self.c.recv()
                if "error" in r: raise RuntimeError(r["error"])
                return r
            except (ConnectionRefusedError, EOFError, OSError):
                self.c = None; time.sleep(2)
        raise RuntimeError("LLM server unreachable")


def calibrate_latency(n=18):
    """Measure single-request (batch=1) latency for varied prompt/output lengths; fit
    t = a + b*n_in + c*n_out by least squares."""
    import numpy as np
    eng = Engine()
    rows = []
    filler = "Observed flows on the port include short TCP and UDP exchanges. "
    for i in range(n):
        reps = [5, 20, 40, 60, 80, 100][i % 6]
        max_new = [40, 80, 120][i % 3]
        msgs = [{"role": "system", "content": "You write text."},
                {"role": "user", "content": filler * reps + f" Now write {max_new} words about networks, item {i}."}]
        eng.generate([msgs], 8)   # warm-up
        eng.torch.cuda.synchronize(); t = time.time()
        (txt, n_in, n_out), = eng.generate([msgs], max_new)
        eng.torch.cuda.synchronize(); el = time.time() - t
        rows.append((n_in, n_out, el)); print(n_in, n_out, round(el, 2), flush=True)
    A = np.array([[1, r[0], r[1]] for r in rows]); y = np.array([r[2] for r in rows])
    coef, *_ = np.linalg.lstsq(A, y, rcond=None)
    pred = A @ coef
    r2 = 1 - ((y - pred) ** 2).sum() / ((y - y.mean()) ** 2).sum()
    json.dump(dict(a=float(coef[0]), b=float(coef[1]), c=float(coef[2]), r2=float(r2), rows=rows,
                   gpu=eng.torch.cuda.get_device_name(0)), open(CALIB, "w"), indent=1)
    print("coef", coef, "R2", r2)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "calibrate":
        calibrate_latency()
    else:
        adapter = sys.argv[2] if len(sys.argv) > 2 and sys.argv[1] in ("--adapters", "--merge") else None
        if len(sys.argv) > 2 and sys.argv[1] == "--merge": adapter = "merge:" + adapter
        Server(adapter=adapter).serve()
