# Glasshouse: Personal Network Traffic Analyzer

Sniffs TCP traffic with Scapy, counts it by protocol (HTTP, HTTPS, FTP, Telnet, SMTP, POP3, IMAP), and flags plaintext credentials. HTTPS is counted but never inspected, because it is encrypted.

**Use only on your own machine or lab network, with fake credentials.**

## UI
```
python3 ui_server.py                 # demo traffic, no root needed
sudo python3 ui_server.py -i wlan0   # live capture of your own traffic
```
Open http://127.0.0.1:8765. Encrypted packets are sealed steel cubes, plaintext ones are amber glass, and a captured credential stops at the checkpoint and glows. Three.js loads from a CDN.

## CLI demo
```
python3 demo_server.py                      # terminal A: fake HTTP login site
sudo python3 analyzer.py -i lo              # terminal B: capture loopback
```
Open http://localhost:8000 and log in as `alice` / `hunter2`. Terminal B prints:
`[!] HTTP plaintext  127.0.0.1 -> 127.0.0.1:8000  password=hunter2`. Ctrl+C prints the protocol summary.

Live LAN traffic: `sudo python3 analyzer.py -i wlan0`. Offline: `python3 analyzer.py --pcap file.pcap`.
Self-check: `python3 test_analyzer.py`.

## Limitations
- Protocols are identified by port, so non-standard ports show as "Other".
- Each packet is analyzed alone (no TCP reassembly), so a secret split across packets can be missed.
- Without monitor mode, you only see your own host's traffic.

## Takeaway
The same login over HTTPS shows up only as an encrypted `HTTPS` count. TLS is what stops this attack.
