#!/usr/bin/env python3
"""Serve the Glasshouse UI on http://127.0.0.1:8765.

  python3 ui_server.py                 # replay demo traffic, no root needed
  sudo python3 ui_server.py -i wlan0   # live capture of your own traffic
"""
import argparse, json, random, threading, time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from scapy.all import IP, TCP, Raw, sniff

import analyzer

PAGE = Path(__file__).with_name("index.html")
events, lock = deque(maxlen=500), threading.Lock()
state = {"mode": "demo", "iface": "", "error": "", "seq": 0, "secrets": 0}


def record(proto, src, dst, port, found):
    with lock:
        state["seq"] += 1
        state["secrets"] += len(found)
        events.append({"id": state["seq"], "t": time.strftime("%H:%M:%S"), "proto": proto,
                       "src": src, "dst": dst, "port": port, "found": found})


analyzer.on_event = record

# (dport, payload, weight); weights keep the demo mostly encrypted, like a real network
DEMO = [
    (443, b"\x17\x03\x03\x00\x28" + bytes(40), 60),
    (80, b"GET /news HTTP/1.1\r\nHost: example.test\r\n\r\n", 14),
    (8000, b"GET /login HTTP/1.1\r\nHost: localhost\r\n\r\n", 6),
    (21, b"220 FTP ready\r\n", 4),
    (25, b"EHLO lab.local\r\n", 3),
    (80, b"GET /cart HTTP/1.1\r\nCookie: session=9f2c41ab7d\r\n\r\n", 3),
    (8000, b"POST /login HTTP/1.1\r\n\r\nusername=alice&password=hunter2", 3),
    (21, b"USER backup\r\n", 1),
    (21, b"PASS letmein99\r\n", 1),
    (110, b"PASS correcthorse\r\n", 1),
]


def demo():
    pkts = [(IP(src="192.168.1.23", dst="192.168.1.9") / TCP(sport=50000, dport=p) / Raw(d), w)
            for p, d, w in DEMO]
    while True:
        analyzer.handle(random.choices([p for p, _ in pkts], [w for _, w in pkts])[0])
        time.sleep(random.uniform(0.12, 0.5))


def live(iface):
    try:
        sniff(iface=iface, filter="tcp", prn=analyzer.handle, store=False)
    except Exception as e:  # usually PermissionError without root
        state.update(mode="demo", error=f"Live capture failed ({e}). Showing demo traffic.")
        demo()


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/api/state":
            since = int(parse_qs(u.query).get("since", ["0"])[0])
            with lock:
                body = json.dumps({**state, "stats": dict(analyzer.stats),
                                   "events": [e for e in events if e["id"] > since]}).encode()
            ctype = "application/json"
        elif u.path == "/":
            body, ctype = PAGE.read_bytes(), "text/html; charset=utf-8"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", help="capture live on this interface (needs root)")
    a = ap.parse_args()
    if a.iface:
        state.update(mode="live", iface=a.iface)
    threading.Thread(target=live if a.iface else demo, args=(a.iface,) if a.iface else (), daemon=True).start()
    print("Glasshouse on http://127.0.0.1:8765")
    ThreadingHTTPServer(("127.0.0.1", 8765), H).serve_forever()
