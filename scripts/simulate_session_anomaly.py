#!/usr/bin/env python3
"""Potential session hijack indicator traffic for lab testing only."""
from scapy.all import IP, TCP, send

dst = "127.0.0.1"
dport = 8080
for i in range(30):
    pkt = IP(src="10.0.0.42", dst=dst) / TCP(sport=13000 + i, dport=dport, flags="PA", seq=9000000 + i * 1000, ack=1)
    send(pkt, verbose=False)
