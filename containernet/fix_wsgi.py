w = "/usr/local/lib/python3.10/dist-packages/ryu/app/wsgi.py"
s = open(w).read()
bad = ("    try:\n    from eventlet.wsgi import ALREADY_HANDLED\nexcept ImportError:\n    ALREADY_HANDLED = b''\n"
       "    _ALREADY_HANDLED = ALREADY_HANDLED\n")
good = ("    try:\n        from eventlet.wsgi import ALREADY_HANDLED\n    except ImportError:\n        ALREADY_HANDLED = b''\n"
        "    _ALREADY_HANDLED = ALREADY_HANDLED\n")
assert bad in s, "pattern not found"
open(w, "w").write(s.replace(bad, good))
print("fixed")
