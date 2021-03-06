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

from gen_traffic import log, log_timestamp, randbytes
from process_run import ARGPacket, inet_aton_integer, inet_ntoa_integer, md5_packet

def sniff_and_replay(alteration=None, delay=None, dev='eth1'):
	log('Sniffing ARG packets')
	while True:
		try:
			scapy.all.sniff(prn=alter_and_replay_packet, store=0,
				filter='ip and proto 253', iface=dev)
		except KeyboardInterrupt:
			log('User requested we stop')
			break
		except socket.error:
			raise
		except Exception as e:
			log('ERROR: {}'.format(e))

def alter_and_replay_packet(pkt, alteration=None, delay=None):
	# Change the TTL so we can avoid receiving our own sends
	ip = pkt.getlayer(scapy.layers.inet.IP)
	if ip.ttl > 25:
		ip.ttl = 20
	else:
		return

	# Hardcode some stuff, I don't care
	delay = .5
	mask = inet_aton_integer("255.255.0.0")

	# How (if) should we alter the packet?
	if alteration is None:
		alteration = random.randint(0, 6)
	
	# Now that we know we actually want this packet, log it
	log_recv(pkt)

	note = ''
	if pkt.haslayer(ARGPacket):
		arg = pkt.getlayer(ARGPacket)

		# What tests should we do?
		# Give each one a 1/8 chance of happening
		tests = [random.choice([True, False, False, False, False, False, False, False, False, False]) for x in range(10)]
		if tests[0]:
			note += 'zeroing signature, '
			arg.sig = 0

		if tests[1]:
			newtype = random.randint(0, 10)
			note += 'changing msg type to {}, '.format(newtype)
			arg.type = newtype

		if tests[2]:
			newlen = random.randint(0, 2 * arg.len)
			note += 'changing msg len to {} from {}, '.format(newlen, arg.len)
			arg.len = newlen

		if tests[3]:
			note += 'zeroing the data, '
			arg.payload = chr(0) * len(arg.payload)

		if tests[4]:
			# We also need to fix the IP length of the packet when we do this
			note += 'removing the data, '
			arg.payload = None
			ip.len = None

		if tests[5]:
			newseq = arg.seq + random.randint(-2000, 2000)
			if newseq < 0:
				newseq = 0
			note += 'changing sequence num from {} to {}, '.format(arg.seq, newseq)
			arg.seq = newseq

		if tests[6]:
			newip = inet_ntoa_integer(inet_aton_integer(ip.src) | (random.getrandbits(32) & ~mask))
			#newip = "172.5.1.1"
			note += 'changing the source ip from {} to {}, '.format(ip.src, newip)
			ip.src = newip

		if tests[7]:
			newip = inet_ntoa_integer(inet_aton_integer(ip.dst) | (random.getrandbits(32) & ~mask))
			note += 'changing the destination ip from {} to {}, '.format(ip.dst, newip)
			ip.dst = newip

	else:
		log('Captured a packet that is not alterable (with this script)')
	
	if delay is not None:
		time.sleep(delay)

	if not note:
		note = 'unaltered replay'

	# Send it back
	print(note)
	log_send(pkt, note=note)
	scapy.all.sendp(pkt, verbose=False, iface='eth1')

########################################
# Utilities
def send(pkt):
	scapy.all.sendp(pkt, verbose=False, iface='eth1')

def randpayload():
	return randbytes(50)

def log_send(pkt, note=''):
	m = md5_packet(pkt)[0]
	ip = pkt.getlayer(scapy.layers.inet.IP)
	log('Sent {}:{} from {} to {}, note:{}'.format(ip.proto, m, ip.src, ip.dst, note))

def log_recv(pkt):
	m = md5_packet(pkt)[0]
	ip = pkt.getlayer(scapy.layers.inet.IP)
	log('Received {}:{} from {} to {}'.format(ip.proto, m, ip.src, ip.dst))

def end_traffic(sig, stack):
	log('User requested we stop')
	sys.exit()

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

	sniff_and_replay()

	return 0

if __name__ == '__main__':
	sys.exit(main(sys.argv))

