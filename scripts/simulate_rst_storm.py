#!/usr/bin/env python3
"""Abnormal RST burst for lab testing only."""
from scapy.all import IP, TCP, send

dst = "127.0.0.1"
dport = 8080
for i in range(100):
    pkt = IP(src="10.0.0.9", dst=dst) / TCP(sport=12000 + i, dport=dport, flags="R")
    send(pkt, verbose=False)
