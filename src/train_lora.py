"""LoRA fine-tuning of the rule synthesizer: SFT on verifier-approved rules, then DPO with the
verifier outcome as the preference signal (Rafailov et al., 2023)."""
import os, sys, json, time, math, random, argparse
import torch, torch.nn.functional as F
from transformers import AutoTokenizer
import lora
from llm_server import MODEL

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
D = os.path.join(ROOT, "results", "sft")


def encode(tok, msgs, target, max_len=900):
    prompt = tok.apply_chat_template(msgs, add_generation_prompt=True, tokenize=False)
    p_ids = tok(prompt, add_special_tokens=False).input_ids
    t_ids = tok(target + "<|im_end|>", add_special_tokens=False).input_ids
    ids = (p_ids + t_ids)[-max_len:]
    n_t = min(len(t_ids), len(ids))
    labels = [-100] * (len(ids) - n_t) + ids[-n_t:]
    return torch.tensor([ids]), torch.tensor([labels])


def target_logits(model, ids, labels):
    """Run the transformer, then the LM head only at positions that predict a target token
    (full-vocabulary logits over the prompt would not fit in 6 GB)."""
    h = model.model(input_ids=ids.cuda()).last_hidden_state[:, :-1]
    lab = labels[:, 1:].cuda()
    m = lab != -100
    return model.lm_head(h[m]).float(), lab[m]


def seq_logp(model, ids, labels):
    logits, lab = target_logits(model, ids, labels)
    lp = torch.log_softmax(logits, -1).gather(-1, lab.unsqueeze(-1)).squeeze(-1)
    return lp.sum().unsqueeze(0), torch.tensor([lab.numel()])


def train_sft(args):
    tok = AutoTokenizer.from_pretrained(MODEL)
    model, n = lora.prepare_train_model(MODEL)
    print("lora modules", n, "trainable", sum(p.numel() for p in model.parameters() if p.requires_grad), flush=True)
    ex = [json.loads(l) for l in open(os.path.join(D, "sft_train.jsonl"))]
    if args.limit: ex = ex[:args.limit]
    if args.exclude_class:
        ex = [e for e in ex if e["cls"] != args.exclude_class]
    params = [p for p in model.parameters() if p.requires_grad]
    opt = torch.optim.AdamW(params, lr=args.lr, weight_decay=0.0)
    steps = math.ceil(len(ex) * args.epochs / args.accum)
    sched = torch.optim.lr_scheduler.LambdaLR(opt, lambda s: min(1.0, (s + 1) / 10) * 0.5 * (1 + math.cos(math.pi * min(s, steps) / steps)))
    model.train()
    t0, step, log = time.time(), 0, []
    rng = random.Random(0)
    for ep in range(args.epochs):
        rng.shuffle(ex)
        run = 0.0
        for i, e in enumerate(ex):
            ids, lab = encode(tok, e["msgs"], e["target"])
            logits, tl = target_logits(model, ids, lab)
            loss = F.cross_entropy(logits, tl)
            (loss / args.accum).backward()
            run += loss.item()
            if (i + 1) % args.accum == 0:
                torch.nn.utils.clip_grad_norm_(params, 1.0)
                opt.step(); sched.step(); opt.zero_grad(set_to_none=True); step += 1
                if step % 10 == 0:
                    el = time.time() - t0
                    print(f"ep {ep} step {step}/{steps} loss {run / args.accum / 10:.4f} {el:.0f}s "
                          f"mem {torch.cuda.max_memory_allocated() / 1e9:.2f}GB", flush=True)
                    log.append(dict(step=step, loss=run / args.accum / 10, t=el)); run = 0.0
    lora.save_adapter(model, args.out)
    json.dump(dict(args=vars(args), log=log, n_examples=len(ex), train_s=time.time() - t0),
              open(args.out + ".json", "w"), indent=1)
    print("saved", args.out, time.time() - t0)


def train_dpo(args):
    tok = AutoTokenizer.from_pretrained(MODEL)
    model, n = lora.prepare_train_model(MODEL)
    # initialise the policy from the SFT adapter; the reference is the same SFT adapter (frozen)
    sd = torch.load(args.init, map_location="cpu")
    mods = dict(model.named_modules())
    for k, v in sd.items():
        mod_name, rest = k.split(".adapters.")
        getattr(mods[mod_name].adapters, "train_" + rest[2:]).data.copy_(v.cuda())
    for m_ in model.modules():   # no dropout: policy and reference log-probs must be comparable
        if isinstance(m_, lora.LoRALinear): m_.drop.p = 0.0
    pairs = [json.loads(l) for l in open(args.pairs)]
    rng = random.Random(0); rng.shuffle(pairs)
    if args.limit: pairs = pairs[:args.limit]
    enc = [(encode(tok, p["msgs"], p["chosen"]), encode(tok, p["msgs"], p["rejected"])) for p in pairs]
    # reference log-probs (policy at initialisation), computed once without grad
    model.eval()
    ref = []
    with torch.no_grad():
        for (c, r) in enc:
            ref.append((seq_logp(model, *c)[0].item(), seq_logp(model, *r)[0].item()))
    print("reference done", flush=True)
    model.train()
    params = [p for p in model.parameters() if p.requires_grad]
    opt = torch.optim.AdamW(params, lr=args.lr)
    t0, step, log, run, acc = time.time(), 0, [], 0.0, 0.0
    for ep in range(args.epochs):
        for i, ((c, r), (rc, rr)) in enumerate(zip(enc, ref)):
            lc, nc = seq_logp(model, *c)
            lr_, _ = seq_logp(model, *r)
            margin = args.beta * ((lc - rc) - (lr_ - rr))
            # DPO + NLL anchor on the chosen response (prevents likelihood displacement of chosen outputs)
            loss = -F.logsigmoid(margin).mean() + args.nll * (-lc / nc.to(lc.device)).mean()
            (loss / args.accum).backward()
            run += loss.item(); acc += float(margin.item() > 0)
            if (i + 1) % args.accum == 0:
                torch.nn.utils.clip_grad_norm_(params, 1.0)
                opt.step(); opt.zero_grad(set_to_none=True); step += 1
                if step % 5 == 0:
                    print(f"dpo step {step} loss {run / (5 * args.accum):.4f} pref-acc {acc / (5 * args.accum):.2f} "
                          f"{time.time() - t0:.0f}s", flush=True)
                    log.append(dict(step=step, loss=run / (5 * args.accum), acc=acc / (5 * args.accum))); run = acc = 0.0
    lora.save_adapter(model, args.out)
    json.dump(dict(args=vars(args), log=log, n_pairs=len(pairs), train_s=time.time() - t0),
              open(args.out + ".json", "w"), indent=1)
    print("saved", args.out)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["sft", "dpo"])
    ap.add_argument("--out", required=True)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--epochs", type=int, default=1)
    ap.add_argument("--accum", type=int, default=8)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--exclude_class", default="")
    ap.add_argument("--init", default="")
    ap.add_argument("--pairs", default="")
    ap.add_argument("--beta", type=float, default=0.1)
    ap.add_argument("--nll", type=float, default=0.0)
    a = ap.parse_args()
    (train_sft if a.mode == "sft" else train_dpo)(a)
