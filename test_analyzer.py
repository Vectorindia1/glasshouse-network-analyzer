from scapy.all import IP, TCP, Raw
import analyzer


def pkt(dport, data=b""):
    return IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=50000, dport=dport) / Raw(data)


http = analyzer.handle(pkt(8000, b"POST / HTTP/1.1\r\n\r\nusername=alice&password=hunter2"))
assert "password=hunter2" in http and "username=alice" in http, http
assert "PASS secret" in analyzer.handle(pkt(21, b"PASS secret\r\n"))
assert any("alice:pw" in f for f in analyzer.handle(pkt(80, b"GET / HTTP/1.1\r\nAuthorization: Basic YWxpY2U6cHc=\r\n\r\n")))
assert analyzer.handle(pkt(443, b"password=hunter2")) == []  # encrypted: never inspected
assert analyzer.stats["HTTPS"] == 1 and analyzer.stats["HTTP"] == 2 and analyzer.stats["FTP"] == 1
print("ok")
