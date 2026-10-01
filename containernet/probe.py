"""Parallel reachability probe: argv[1] = JSON list of [ip, proto, port]; prints JSON list of booleans.
TCP: connect, send, expect one byte back (request + response). UDP: send, expect echo (2 tries)."""
import json, socket, sys
from concurrent.futures import ThreadPoolExecutor

T = 1.5


def one(t):
    ip, proto, port = t
    try:
        if proto == "tcp":
            s = socket.create_connection((ip, port), timeout=T)
            s.settimeout(T); s.sendall(b"x"); ok = s.recv(1) == b"y"; s.close(); return ok
        for _ in range(2):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(T)
            s.sendto(b"x", (ip, port))
            try:
                d, _ = s.recvfrom(64); s.close()
                if d == b"x": return True
            except socket.timeout:
                s.close()
        return False
    except OSError:
        return False


targets = json.loads(sys.argv[1])
with ThreadPoolExecutor(max_workers=16) as ex:
    print(json.dumps(list(ex.map(one, targets))))
