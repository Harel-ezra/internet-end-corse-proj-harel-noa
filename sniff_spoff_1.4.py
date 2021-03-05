#!/usr/bin/env python3
from scapy.all import *

def send_icmp(pkt):
	print("sent ICMP packets..")
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

def send_arp(pkt):
	print("send ARP packets..")
	e=Ether()
	e.dst=pkt[Ether].src
	e.src="08:00:27:80:35:06"
	a=ARP()
	a.psrc=pkt[ARP].pdst
	a.pdst=pkt[ARP].psrc
	a.op=2
	a.hwsrc="08:00:27:80:35:06"
	a.hwdst=pkt[ARP].hwsrc
	send(e/a)
	
def catch_pkt(pkt):
	if ICMP in pkt:
		if pkt[ICMP].type==8:
			send_icmp(pkt)
	else:
		if ARP in pkt:
			send_arp(pkt)
					
pkt = sniff(iface=['enp0s3','br-b7db7f7b9534'], filter='icmp or arp', prn=catch_pkt)

