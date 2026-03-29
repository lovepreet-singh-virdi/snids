#!/usr/bin/env python3
"""
High-volume SYN mix for lab testing only.
Generates bursts from multiple source IPs and rotating destination ports to exercise SYN-flood and port-scan rules.
"""
from scapy.all import IP, TCP, send

dst = "127.0.0.1"
base_dport = 8000
total = 800  # total SYNs
sources = [f"10.0.0.{i}" for i in range(1, 9)]

pkts = []
for i in range(total):
    src = sources[i % len(sources)]
    dport = base_dport + (i % 40)  # rotate across 40 ports
    sport = 20000 + i
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S"))

send(pkts, verbose=False)
