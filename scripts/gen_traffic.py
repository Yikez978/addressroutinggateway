#!/usr/bin/env python
from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division

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

MAX_PACKET_SIZE = 1400

# Support functions
def log(msg):
	print('{} {} {}'.format(time.time(), 'LOG4', msg))

def log_timestamp():
	log('START: Starting at {}'.format(time.strftime('%d %b %Y %H:%M:%S')))

def log_local_addr(addr):
	ip, port = addr
	ip = socket.gethostbyname(socket.gethostname())
	log('LOCAL ADDRESS: {}:{}'.format(ip, port))

def log_send(ip, port, buf):
	m = hashlib.md5()
	m.update(buf)
	log('Sent {} to {}:{}'.format(m.hexdigest(), ip, port))

def log_recv(ip, port, buf):
	m = hashlib.md5()
	m.update(buf)
	log('Received {} from {}:{}'.format(m.hexdigest(), ip, port))
	pass

def randbytes(size):
	#return b''.join([chr(random.randrange(0, 255)) for x in range(size)])
	return b''.join([random.choice(string.ascii_lowercase) for x in range(size)])

# Basic senders and receivers
def tcp_sender(ip, port, delay=1, size=None):
	log('Starting a TCP sender to {}:{}'.format(ip, port))

	connected = False
	while not connected:
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((ip, port))
			connected = True
		except socket.error:
			s.close()
			connected = False
			time.sleep(1)
			log('Retrying connection to {}:{}'.format(ip, port))

	s.settimeout(1)
	
	log_local_addr(s.getsockname())

	try:
		while True:
			if size is not None:
				buf = randbytes(size)
			else:
				buf = randbytes(random.randrange(0, MAX_PACKET_SIZE))

			# Delay next packet
			time.sleep(delay)
			s.sendall(buf) # TBD, change to send and ensure each packet gets logged
			log_send(ip, port, buf)

			# Get response back?
			try:
				buf = s.recv(MAX_PACKET_SIZE)
				if not buf:
					break
				log_recv(ip, port, buf)
			except socket.timeout:
				continue
	except socket.error:
		log('Error working with socket, likely closed by remote end')
	except KeyboardInterrupt:
		log('User requested we stop')

	log('Connection to {}:{} lost'.format(ip, port))
	s.close()

def tcp_receiver(port, echo=False, size=None):
	log('Starting a TCP receiver on port {}'.format(port))

	stopper = threading.Event()

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind(('', port))
	s.listen(1)

	log_local_addr(s.getsockname())

	try:
		while True:
			c_sock, addr = s.accept()
			r_ip, r_port = addr
			handler = threading.Thread(target=tcp_receiver_handler,
				args=(c_sock, r_ip, r_port, stopper, echo, size))
			handler.start()
	except KeyboardInterrupt:
		log('Telling handlers to die')
		stopper.set()

	log('TCP listener on port {} dying'.format(port))
	s.close()

def tcp_receiver_handler(conn, ip, port, stopper, echo=False, size=None):
	log('Accepting TCP connection from {}:{}'.format(ip, port))

	conn.settimeout(1)

	try:
		while not stopper.is_set():
			try:
				buf = conn.recv(MAX_PACKET_SIZE)
				if not buf:
					break
				log_recv(ip, port, buf)
			except socket.timeout:
				# Check if we're supposed to be done
				continue

			if not echo:
				if size is not None:
					buf = randbytes(size)
				else:
					buf = randbytes(random.randrange(0, MAX_PACKET_SIZE))

			conn.sendall(buf)
			log_send(ip, port, buf)
	except socket.error:
		pass
	except KeyboardInterrupt:
		log('User requested we stop')

	conn.close()
	log('Connection to {}:{} lost'.format(ip, port))
		
def udp_sender(ip, port, delay=1, size=None):
	log('Starting a UDP sender to {}:{}'.format(ip, port))

	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.settimeout(1)
	
	log_local_addr(s.getsockname())

	try:
		while True:
			# Generate random data of the given size
			if size is not None:
				buf = randbytes(size)
			else:
				buf = randbytes(random.randrange(0, MAX_PACKET_SIZE))

			# Delay next packet
			time.sleep(delay)
			
			# Send
			s.sendto(buf, (ip, port))
			log_send(ip, port, buf)

			# Get response back?
			try:
				buf = s.recv(MAX_PACKET_SIZE)
				if not buf:
					break
				log_recv(ip, port, buf)
			except socket.timeout:
				continue
	except KeyboardInterrupt:
		log('User requested we stop')
	
	log('UDP sender to {}:{} dying'.format(ip, port))
	s.close()

def udp_receiver(port, echo=False, size=None):
	log('Starting a UDP receiver on port {}'.format(port))
	
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.bind(('', port))
	
	log_local_addr(s.getsockname())

	try:
		while True:
			buf, addr = s.recvfrom(MAX_PACKET_SIZE)
			log_recv(addr[0], addr[1], buf)

			# Send back either their data or some gibberish
			if not echo:
				if size is not None:
					buf = randbytes(size)
				else:
					buf = randbytes(random.randrange(0, MAX_PACKET_SIZE))
			
			s.sendto(buf, addr)
			log_send(addr[0], addr[1], buf)
	except KeyboardInterrupt:
		log('User requested we stop')

	log('UDP listener on port {} dying'.format(port))
	s.close()

# Tell whatever generator we're running to die
def end_traffic(sig, stack):
	raise KeyboardInterrupt

# Run the correct host generator
def main(argv):
	# Parse command line
	parser = argparse.ArgumentParser(add_help=False, description='Process an ARG test network run')
	#parser.add_argument('host', default=socket.gethostname(), nargs='?',
	#	help='Host to run as (ext1, protA1, etc). Defaults to current hostname')
	parser.add_argument('-t', '--type', required=True, help='TCP of traffic to work with (TCP, UDP, or ARG)')
	parser.add_argument('-h', '--host', help='Host to send to')
	parser.add_argument('-l', '--listen', action='store_true', help='For TCP or UDP, \
			makes this end into the server')
	parser.add_argument('-p', '--port', type=int, help='Port to listen on')

	parser.add_argument('-d', '--delay', type=float, default=1,
			help='Number of seconds to wait between packets. Floating point values \
			may be given for finer control (ie, 0.5)')
	parser.add_argument('-e', '--echo', action='store_true', help='Listener: Echo all data received')
	parser.add_argument('-s', '--size', type=int, help='Size of packets to send. \
			Unspecified creates randomly-sized packets. Ignored if echoing')
	
	parser.add_argument('-o', '--output', default=None, help='Logs to the given file, rather than stdout')

	args = parser.parse_args(argv[1:])

	# Log to file?
	output_file = None
	if args.output is not None:
		output_file = open(args.output, 'w')
		sys.stdout = output_file

	# What should we run?
	signal.signal(signal.SIGINT, end_traffic)
	signal.signal(signal.SIGTERM, end_traffic)
	try:
		log_timestamp()
		if args.type.lower() == 'tcp':
			if args.listen:
				tcp_receiver(args.port, echo=args.echo, size=args.size)
			else:
				tcp_sender(args.host, args.port, delay=args.delay, size=args.size)
		elif args.type.lower() == 'udp':
			if args.listen:
				udp_receiver(args.port, echo=args.echo, size=args.size)
			else:
				udp_sender(args.host, args.port, delay=args.delay, size=args.size)
		else:
			log('Type {} not yet handled'.format(args.type))
	finally:
		# Close log file
		if output_file is not None:
			sys.stdout = sys.__stdout__
			output_file.close()

	return 0

if __name__ == '__main__':
	sys.exit(main(sys.argv))

