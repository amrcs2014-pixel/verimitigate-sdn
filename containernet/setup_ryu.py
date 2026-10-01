"""Make Ryu 4.34 importable on Python 3.10 (compatibility shims only; no behavioural change)."""
import os, site, re
sp = [p for p in site.getsitepackages() if p.endswith("dist-packages") and "/usr/local" in p][0]
# 1. collections ABC aliases removed in Python 3.10
open(os.path.join(sp, "sitecustomize.py"), "w").write(
    "import collections, collections.abc\n"
    "for _n in ('MutableMapping', 'Mapping', 'Sequence', 'MutableSet', 'Callable', 'Iterable', 'Hashable'):\n"
    "    if not hasattr(collections, _n):\n"
    "        setattr(collections, _n, getattr(collections.abc, _n))\n")
# 2. eventlet >= 0.30.3 removed ALREADY_HANDLED
w = os.path.join(sp, "ryu", "app", "wsgi.py")
s = open(w).read()
if "except ImportError:\n    ALREADY_HANDLED" not in s:
    s = s.replace("from eventlet.wsgi import ALREADY_HANDLED",
                  "try:\n    from eventlet.wsgi import ALREADY_HANDLED\nexcept ImportError:\n    ALREADY_HANDLED = b''")
    open(w, "w").write(s)
print("patched", sp)
