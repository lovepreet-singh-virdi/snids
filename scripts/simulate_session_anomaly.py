#!/usr/bin/env python3
"""
Session-anomaly simulator for lab testing only.
Mixes high seq jumps and duplicate ACK patterns to exercise hijack heuristics.
"""
from scapy.all import IP, TCP, send

dst = "127.0.0.1"
dport = 8080
src = "10.0.0.42"
pkts = []

# Large seq jumps (established flow mimic)
for i in range(80):
    pkts.append(IP(src=src, dst=dst) / TCP(sport=13000, dport=dport, flags="PA", seq=9_000_000 + i * 1500, ack=1))

# Duplicate ACK burst
for i in range(40):
    pkts.append(IP(src=src, dst=dst) / TCP(sport=13000, dport=dport, flags="A", seq=1_000_000, ack=55555))

send(pkts, verbose=False)
