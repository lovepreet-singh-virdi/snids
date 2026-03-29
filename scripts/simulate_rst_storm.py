#!/usr/bin/env python3
"""
RST storm for lab testing only.
Generates multiple short bursts from a few sources to trigger reset-spike detectors.
"""
from scapy.all import IP, TCP, send

dst = "127.0.0.1"
base_dport = 8080
sources = ["10.0.0.9", "10.0.0.10", "10.0.0.11"]
bursts = 5
per_burst = 80

pkts = []
for b in range(bursts):
    for i in range(per_burst):
        src = sources[(b + i) % len(sources)]
        dport = base_dport + (i % 5)
        sport = 30000 + b * 500 + i
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="R"))

send(pkts, verbose=False)
