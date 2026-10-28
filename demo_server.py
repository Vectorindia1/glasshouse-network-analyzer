#!/usr/bin/env python3
"""Fake unencrypted login site on localhost:8000 for the demo."""
from http.server import BaseHTTPRequestHandler, HTTPServer

FORM = b'<form method=post>user <input name=username><br>pass <input name=password type=password><br><button>Log in</button></form>'


class H(BaseHTTPRequestHandler):
    def _send(self, body):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(FORM)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self._send(b"logged in (not really)")


HTTPServer(("127.0.0.1", 8000), H).serve_forever()
