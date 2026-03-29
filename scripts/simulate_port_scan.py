#!/usr/bin/env python3
"""
Port-scan simulator for lab testing only.
Sends SYN probes across many destination ports from one source to trigger the PORT_SCAN detector.
"""
from scapy.all import IP, TCP, send

dst = "127.0.0.1"
src = "10.1.1.50"
ports = list(range(7000, 7100))  # 100 distinct ports

pkts = [IP(src=src, dst=dst) / TCP(sport=40000 + i, dport=p, flags="S") for i, p in enumerate(ports)]

send(pkts, verbose=False)
