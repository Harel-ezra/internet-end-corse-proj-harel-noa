#!/usr/bin/env python3
from scapy.all import *
def trace_route():
	a = IP()
	a.dst = '1.1.1.1'
	a.ttl = 9
	ls(a)
	b = ICMP()
	p=a/b
	send(p)
		
trace_route()
