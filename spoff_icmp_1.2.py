#!/usr/bin/env python3
from scapy.all import *
def send_icmp():
	a=IP()
	a.dst='128.230.0.0'	
	ls(a)
	b=ICMP()
	p=a/b
	send(p)
	
send_icmp()

