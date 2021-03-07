#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
	pkt.show()

pkt = sniff(iface='br-b7db7f7b9534', filter='icmp', prn=print_pkt)
