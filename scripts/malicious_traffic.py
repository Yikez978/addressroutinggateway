#!/usr/bin/env python
from __future__ import absolute_import
from __future__ import print_function

import sys
import argparse
import importlib
import socket
import time
import random
import string
import threading
import hashlib
import signal

import scapy.all

from gen_traffic import log, log_timestamp, randbytes, end_traffic
from process_run import ARGPacket, inet_aton_integer, inet_ntoa_integer, md5_packet
#scapy.all.bind_layers(scapy.layers.inet.IP, ARGPacket, proto=253)

def spam_malformed(delay):
	#send(IP(dst="10.1.1.5", ihl=2, version=3)/ICMP())
	pass

def spam_traffic(delay, proto, from_ip, to_ip, from_port=None, to_port=None, from_ip_mask="255.255.255.255", to_ip_mask="255.255.255.255", payload=None):
	try:
		fmask = inet_aton_integer(from_ip_mask)
		tmask = inet_aton_integer(to_ip_mask)
		from_ip = inet_aton_integer(from_ip) & fmask
		to_ip = inet_aton_integer(to_ip) & tmask

		while True:
			# Generate random parts of packet
			fip = inet_ntoa_integer(from_ip | (random.getrandbits(32) & ~fmask))
			tip = inet_ntoa_integer(to_ip | (random.getrandbits(32) & ~tmask))

			if from_port is None:
				fport = random.randrange(0, 65535)
			else:
				fport = from_port

			if to_port is None:
				tport = random.randrange(0, 65535)
			else:
				tport = to_port

			# Stop, packet time
			ip = scapy.layers.inet.IP(src=fip, dst=tip)
			if proto == 253:
				print('tbd')
			elif proto == 17:
				lower = scapy.layers.inet.UDP(sport=fport, dport=tport)
			elif proto == 6:
				lower = scapy.layers.inet.TCP(sport=fport, dport=tport)
			else:
				raise Exception('Unknown protocol rquested')
			
			pkt = ip / lower
			if payload is not None:
				if hasattr(payload, '__call__'):
					pkt = pkt / payload()
				else:
					pkt = pkt / payload

			pkt.show()
			log_send(proto, fip, port, buf, is_valid)
			send(pkt)
			
			time.sleep(delay)
	except KeyboardInterrupt:
		log('User requested we stop')

def sniff_and_replay():
	try:
		log('Sniffing ARG packets')
		scapy.all.sniff(prn=alter_and_replay_packet, filter='proto 253', store=0)
	except KeyboardInterrupt:
		log('User requested we stop')

def alter_and_replay_packet(pkt, alteration=None, delay=None):
	log_recv(pkt)

	# How (if) should we alter the packet?
	if alteration is None:
		alteration = random.randint(0, 5)

	# If none of these are matched, intentionally leave the packet the
	# same for a straight replay
	if alteration == 0:
		pass
	
	if delay is not None:
		time.sleep(delay)

	# Send it back
	send(pkt)
	log_send(pkt)

########################################
# Utilities
def send(pkt):
	scapy.all.send(pkt, verbose=False)

def randpayload():
	return randbytes(50)

def log_send(pkt, is_valid=False):
	m = md5_packet(pkt)
	ip = pkt.getlayer(scapy.layers.inet.IP)
	log('Sent {} {}:{} from {} to {}'.format('valid' if is_valid else 'invalid',
		ip.proto, m.hexdigest(), ip.src, ip.dst))

def log_recv(pkt, is_valid=False):
	m = md5_packet(pkt)
	ip = pkt.getlayer(scapy.layers.inet.IP)
	log('Sent {} {}:{} from {} to {}'.format('valid' if is_valid else 'invalid',
		ip.proto, m.hexdigest(), ip.src, ip.dst))

def main(argv):
	parser = argparse.ArgumentParser(description='Generate malicious ARG traffic in various ways')
	parser.add_argument('-o', '--output', default=None, help='Logs to the given file, rather than stdout')
	args = parser.parse_args(argv[1:])

	# Log to file?
	output_file = None
	if args.output is not None:
		output_file = open(args.output, 'w')
		sys.stdout = output_file

	# Die cleanly
	signal.signal(signal.SIGINT, end_traffic)
	signal.signal(signal.SIGTERM, end_traffic)

	#spam_traffic(2, 17, "172.100.0.1", "172.100.0.1", 23, 45, from_ip_mask="255.255.0.0", payload=randpayload)
	#spam_traffic(2, 17, "172.100.0.1", "172.100.0.1", 23, 45)
	sniff_and_replay()

	return 0

if __name__ == '__main__':
	sys.exit(main(sys.argv))

