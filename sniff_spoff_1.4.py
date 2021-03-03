#!/usr/bin/env python3
from scapy.all import *

def send_icmp(pkt):

	a=IP()
	a.dst=pkt[IP].src
	a.src=pkt[IP].dst
	b=ICMP()
	b.type=0
	b.id=pkt[ICMP].id
	b.seq=pkt[ICMP].seq
	c=Raw()
	c.load=pkt[Raw].load
	p=a/b/c
	send(p)

def send_arp(pkt)
	a=ARP()
	
	
def catch_pkt(pkt):
	if ICMP in pkt:
		if pkt[ICMP].type==8:
			send_icmp(pkt)
	else:
		if ARP in pkt:
			
			pkt.show()
			
pkt = sniff(iface=['enp0s3','br-b7db7f7b9534'], filter='arp' or 'icmp', prn=catch_pkt)

