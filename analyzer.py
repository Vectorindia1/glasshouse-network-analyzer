#!/usr/bin/env python3
"""Classify TCP traffic by protocol and flag plaintext credentials. Own network only."""
import argparse, base64, re
from collections import Counter
from scapy.all import IP, TCP, Raw, rdpcap, sniff

# ponytail: port-based classification, misses non-standard ports; upgrade = payload sniffing
PORTS = {80: "HTTP", 8000: "HTTP", 8080: "HTTP", 443: "HTTPS", 21: "FTP",
         23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP"}
PLAIN = set(PORTS.values()) - {"HTTPS"}
SECRET = re.compile(r"(?i)\b(?:user(?:name)?|login|pass(?:word|wd)?|pwd|token)=[^&\s]+"
                    r"|^(?:USER|PASS|LOGIN|AUTH)\b.*$|^Cookie:.*$", re.M)
BASIC = re.compile(r"Authorization: Basic (\S+)")

stats = Counter()
on_event = None  # optional hook(proto, src, dst, dport, found), used by ui_server.py


def classify(pkt):
    t = pkt[TCP]
    return PORTS.get(t.dport) or PORTS.get(t.sport) or "Other"


def findings(proto, payload):
    out = [m.group(0).strip() for m in SECRET.finditer(payload)]
    for b in BASIC.findall(payload):
        try:
            out.append("Basic auth " + base64.b64decode(b).decode(errors="replace"))
        except ValueError:
            pass
    return out


def handle(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return []
    proto = classify(pkt)
    stats[proto] += 1
    found = []
    if proto in PLAIN and pkt.haslayer(Raw):
        found = findings(proto, pkt[Raw].load.decode(errors="replace"))
    for f in found:
        # ponytail: per-packet only, no TCP reassembly; a secret split across packets is missed
        print(f"\033[91m[!] {proto} plaintext  {pkt[IP].src} -> {pkt[IP].dst}:{pkt[TCP].dport}  {f}\033[0m")
    if on_event:
        on_event(proto, pkt[IP].src, pkt[IP].dst, pkt[TCP].dport, found)
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", default="wlan0")
    ap.add_argument("--pcap", help="analyze a capture file instead of sniffing live")
    a = ap.parse_args()
    try:
        if a.pcap:
            for p in rdpcap(a.pcap):
                handle(p)
        else:
            sniff(iface=a.iface, filter="tcp", prn=handle, store=False)
    except KeyboardInterrupt:
        pass
    print("\n--- summary ---")
    for proto, n in stats.most_common():
        print(f"{proto:8} {n}{'  (encrypted)' if proto == 'HTTPS' else ''}")


if __name__ == "__main__":
    main()
