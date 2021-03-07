#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
	print("start sniffing..")
	pkt.show()
	
print("start sniffing..")
pkt = sniff(iface=['enp0s3','br-b7db7f7b9534'], filter='icmp', prn=print_pkt)
