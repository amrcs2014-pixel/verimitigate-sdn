"""Service responder for Containernet hosts: TCP ports answer one byte, UDP ports echo."""
import socket, sys, threading


def tcp(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(128)
    while True:
        c, _ = s.accept()
        try:
            c.settimeout(2); c.recv(16); c.sendall(b"y")
        except OSError:
            pass
        finally:
            c.close()


def udp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", port))
    while True:
        d, a = s.recvfrom(64)
        s.sendto(d, a)


for spec in sys.argv[1:]:
    proto, port = spec.split(":")
    threading.Thread(target=tcp if proto == "tcp" else udp, args=(int(port),), daemon=True).start()
threading.Event().wait()
