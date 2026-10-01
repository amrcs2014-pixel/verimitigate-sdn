"""Minimal LoRA (Hu et al., 2022) for Qwen2.5 on a 6-GB Pascal GPU, without extra packages.

Training: frozen fp16-stored base weights are used through a custom autograd function that
computes in fp32 and saves only the fp16 weight (so no fp32 copies are kept for backward);
non-Linear parameters (embeddings, norms) are held in fp32, so activations are fp32.
Inference (server): adapters are added on top of the fp16 model; several adapters can be
registered and switched per batch.
"""
import math, os, torch, torch.nn as nn, torch.nn.functional as F

TARGETS = ("q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj")


class _FrozenLinear(torch.autograd.Function):
    @staticmethod
    def forward(ctx, x, w, b):
        ctx.save_for_backward(w)
        y = x.float() @ w.float().t()
        if b is not None: y = y + b.float()
        return y

    @staticmethod
    def backward(ctx, gy):
        (w,) = ctx.saved_tensors
        return gy @ w.float(), None, None


class LoRALinear(nn.Module):
    def __init__(self, base: nn.Linear, r=16, alpha=32, dropout=0.05, train_mode=True):
        super().__init__()
        self.base = base
        for p in self.base.parameters(): p.requires_grad_(False)
        self.r, self.scale = r, alpha / r
        self.train_mode = train_mode
        self.drop = nn.Dropout(dropout)
        self.adapters = nn.ParameterDict()
        self.active = None
        if train_mode:
            self.add("train")
            self.active = "train"

    def add(self, name, A=None, B=None):
        dev = self.base.weight.device
        if A is None:
            A = torch.empty(self.r, self.base.in_features, device=dev)
            nn.init.kaiming_uniform_(A, a=math.sqrt(5))
            B = torch.zeros(self.base.out_features, self.r, device=dev)
        self.adapters[name + "_A"] = nn.Parameter(A.float().to(dev), requires_grad=self.train_mode)
        self.adapters[name + "_B"] = nn.Parameter(B.float().to(dev), requires_grad=self.train_mode)

    def forward(self, x):
        if self.train_mode:
            y = _FrozenLinear.apply(x, self.base.weight, self.base.bias)
        elif x.shape[-2] > 1:   # inference prefill: fp32 compute on fp16 weights
            y = F.linear(x.float(), self.base.weight.float(),
                         None if self.base.bias is None else self.base.bias.float()).to(x.dtype)
        else:
            y = F.linear(x, self.base.weight, self.base.bias)
        if self.active is not None:
            A = self.adapters[self.active + "_A"]; B = self.adapters[self.active + "_B"]
            d = (self.drop(x.float()) if self.train_mode else x.float()) @ A.t() @ B.t() * self.scale
            y = y + d.to(y.dtype)
        return y


def inject(model, r=16, alpha=32, dropout=0.05, train_mode=True):
    n = 0
    for name, mod in list(model.named_modules()):
        for t in TARGETS:
            if hasattr(mod, t) and isinstance(getattr(mod, t), nn.Linear):
                setattr(mod, t, LoRALinear(getattr(mod, t), r, alpha, dropout, train_mode)); n += 1
    return n


def lora_state(model, name="train"):
    return {k: v.detach().cpu() for k, v in model.state_dict().items() if f"adapters.{name}_" in k}


def save_adapter(model, path, name="train"):
    sd = {k.replace(f"adapters.{name}_", "adapters.X_"): v for k, v in lora_state(model, name).items()}
    torch.save(sd, path)


def register_adapter(model, path, name):
    """Load a saved adapter into an inference model (after inject(train_mode=False))."""
    sd = torch.load(path, map_location="cpu")
    mods = dict(model.named_modules())
    groups = {}
    for k, v in sd.items():
        mod_name, rest = k.split(".adapters.")
        groups.setdefault(mod_name, {})[rest[2:]] = v
    for mod_name, ab in groups.items():
        mods[mod_name].add(name, ab["A"], ab["B"])


def set_active(model, name):
    for m in model.modules():
        if isinstance(m, LoRALinear): m.active = name


def load_adapter(model, path, name="default"):
    inject(model, train_mode=False)
    register_adapter(model, path, name)
    set_active(model, name)


def prepare_train_model(path):
    from transformers import AutoModelForCausalLM
    m = AutoModelForCausalLM.from_pretrained(path, dtype=torch.float16)
    # non-Linear params (embeddings / norms) in fp32 so the residual stream is fp32
    lin = {id(p) for mod in m.modules() if isinstance(mod, nn.Linear) for p in mod.parameters()}
    emb = m.get_input_embeddings().weight
    for n_, p in m.named_parameters():
        if id(p) not in lin or p is emb:
            p.data = p.data.float()
    for p in m.parameters(): p.requires_grad_(False)
    # lm_head is tied to the (now fp32) embedding: route it through the frozen fn as well
    head = m.lm_head
    head.forward = (lambda self_: (lambda x: _FrozenLinear.apply(x, self_.weight, None)))(head)
    n = inject(m, train_mode=True)
    m.cuda()
    m.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
    m.config.use_cache = False
    return m, n
