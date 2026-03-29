#!/usr/bin/env python3
"""
Low-severity session anomaly simulator.
Emits a short burst of duplicate ACKs on one flow to trigger the POTENTIAL_SESSION_HIJACK (duplicate-ack pattern) rule,
which is classified as low severity.
"""
from scapy.all import IP, TCP, send

dst = "127.0.0.1"
src = "10.1.1.60"
dport = 9090
sport = 14000
dup_acks = 25  # keep small to stay low-severity

pkts = [
    IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=1_000_000, ack=22222)
    for _ in range(dup_acks)
]

send(pkts, verbose=False)
