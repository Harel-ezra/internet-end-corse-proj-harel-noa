#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
	pkt.show()

pkt = sniff(iface='br-b7db7f7b9534', filter='dst net 216.58.204.78', prn=print_pkt)
