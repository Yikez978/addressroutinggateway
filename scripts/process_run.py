#!/usr/bin/env python
from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division

import sys
import os
import os.path
import pcap
import sqlite3
import argparse
import re
from glob import glob

IP_REGEX='''(?:\d{1,3}\.){3}\d{1,3}'''
PACKET_ID_REGEX='''p:([0-9]+) s:({0}):([0-9]+) d:({0}):([0-9]+) hash:([a-z0-9]+)'''.format(IP_REGEX)

# Times on each host may not match up perfectly. How many second on either side do we allow?
TIME_SLACK=5

def create_schema(db):
	# Schema:
	# systems
	#	- id (PK)
	#	- name
	#	- ip (index) - in the case of gateways, the internal IP
	#	- base ip (NULL) - only for gateways, the external base IP
	#	- ip mask (NULL) - gateways, external IP mask
	#
	# reasons
	#	- id (PK)
	#	- msg (NOT NULL)
	#
	# packets
	#	- id (PK)
	#	- system_id (foreign: systems.id) - system this packet was seen/sent on
	#	- log_line (int) - Line in the log file (of the host we saw it on) that corresponds to this entry
	#	- time (int) - time in seconds, relative to the start of the experiment
	#	- is_send (bool)
	#	- is_valid (bool) - true if the sender believes this packet SHOULD reach its destination
	#			(ie, a spoofed packet may not be expected to work)
	#	- proto (int) - protocol of this packet
	#	- src_ip 
	#	- dest_ip
	#	- src_id (foreign: packet.id)
	#	- dest_id (foreign: packet.id)
	#	- hash (index) - MD5 hash of packet data, after the transport layer
	#	- next_hop_id (foreign: packet.id) - If this packet was transformed, then next_hop_id is the ID of the
	#		transformed packet. If this field is NULL on a sent packet, it was lost at this point and
	#		reason_id points to a description of why
	#	- reason_id (foreign: reseasons.id) - Text describing what happened with this packet
	#
	# transforms
	#	- id (PK)
	#	- gate_id (foreign: system.id)
	#	- in_id (foreign: packet.id)
	#	- out_id (foreign: packet.id)
	#	- reason_id (foreign: packet.id)
	c = db.cursor()	
	c.execute('''CREATE TABLE IF NOT EXISTS systems (
						id INTEGER, name VARCHAR(25), ip INT, base_ip INT, mask INT,
						PRIMARY KEY(id ASC))''')
	
	c.execute('''CREATE TABLE IF NOT EXISTS reasons (id INTEGER, msg VARCHAR(255),
						PRIMARY KEY(id ASC))''')

	c.execute('''CREATE TABLE IF NOT EXISTS packets (
						id INTEGER,
						system_id INTEGER,
						log_line INT,
						time INTEGER,
						is_send TINYINT,
						is_valid TINYINT DEFAULT 1,
						proto SHORTINT,
						src_ip INT,
						dest_ip INT,
						src_id INT,
						dest_id INT,
						hash CHARACTER(32),
						next_hop_id INT DEFAULT NULL,
						reason_id INT,
						PRIMARY KEY (id ASC))''')
	
	c.close()

##############################################
# Manange reasons table
def add_reason(db, reason):
	id = get_reason(db, reason)
	if id is not None:
		return id
	
	c = db.cursor()
	c.execute('INSERT INTO reasons (msg) VALUES (?)', (reason,))
	return c.lastrowid

def get_reason(db, reason):
	c = db.cursor()
	c.execute('SELECT id FROM reasons WHERE msg=?', (reason,))
	r = c.fetchone()
	if r is not None:
		return r[0]
	else:
		return None

##############################################
# Manange system table
def add_all_systems(db, logdir):
	print('Adding all systems to database')

	for logName in glob('{}/*.log'.format(logdir)):
		# Determine what type of log this is. Alters parsing and processing
		name = os.path.basename(logName)
		name = name[:name.find('-')]

		print('\tFound {} with log {}'.format(name, logName))

		isGate = name.startswith('gate')
		isProt = name.startswith('prot')
		isExt = name.startswith('ext')
		
		with open(logName) as log:
			if isGate:
				add_gate(db, name, log)
			else:
				add_client(db, name, log)

def add_gate(db, name, log):
	ip = None
	for line in log:
		if line.find('Internal IP') != -1:
			m = re.search('''Internal IP: ({0}).+IP: ({0}).+mask: ({0})'''.format(IP_REGEX), line)
			if m is None:
				raise IOError('Found address line, but unable to parse it for {}'.format(name))

			ip = m.group(1)
			base = m.group(2)
			mask = m.group(3)
			break

	if ip is None:
		raise IOError('Unable to find address from log file for {}'.format(name))
	
	add_system(db, name, ip, base, mask)

def add_client(db, name, log):
	# Finds the client's IP address and adds it to the database
	ip = None
	for line in log:
		if line.find('LOCAL ADDRESS') != -1:
			m = re.search('''({}):(\d+)'''.format(IP_REGEX), line)
			if m is None:
				raise IOError('Found local address line, but unable to parse it for {}'.format(name))

			ip = m.group(1)
			port = m.group(2)
			break
	
	if ip is None:
		raise IOError('Unable to parse log file for {}. Bad format?'.format(name))

	add_system(db, name, ip)

def add_system(db, name, ip, ext_base=None, ext_mask=None):
	# Add system only if it doesn't already exist. Otherwise, just return the rowid
	id = get_system(db, name=name)
	if id is not None:
		return id

	# Convert IPs/mask to decimal
	if type(ip) is str:
		ip = inet_aton_integer(ip)
	if type(ext_base) is str:
		ext_base = inet_aton_integer(ext_base)
	if type(ext_mask) is str:
		ext_mask = inet_aton_integer(ext_mask)

	# Actually add
	c = db.cursor()
	if not ext_base:
		c.execute('INSERT INTO systems (name, ip) VALUES (?, ?)', (name, ip))
		return c.lastrowid
	else:
		c.execute('INSERT INTO systems (name, ip, base_ip, mask) VALUES (?, ?, ?, ?)',
			(name, ip, ext_base, ext_mask))
		return c.lastrowid

def get_system(db, name=None, ip=None, id=None):
	# Gets a system ID based on the given name or ip
	if name is not None:
		c = db.cursor()
		c.execute('SELECT id FROM systems WHERE name=?', (name,))
		r = c.fetchone()
		c.close()

		if r is not None:
			return r[0]
		else:
			return None
	
	elif ip is not None:
		# Convert IPs/mask to decimal
		if type(ip) is str:
			ip = inet_aton_integer(ip)

		c = db.cursor()
		c.execute('SELECT id, ip, name FROM systems WHERE ip=? OR (mask & ? = mask & base_ip)', (ip, ip))
		rows = c.fetchall()
		c.close()

		if len(rows) == 1:
			return rows[0][0]
		elif len(rows) > 1:
			for r in rows:
				if r[1] == ip:
					return r[0]

			print(rows)
			raise Exception('Found multiple systems matching IP {}, but none were an exact match. Bad configuration?'.format(ip))
		else:
			return None

	elif id is not None:
		c = db.cursor()
		c.execute('SELECT id, ip, name FROM systems WHERE id=?', (id,))
		r = c.fetchone()
		c.close()

		return r

	else:
		raise Exception('Name or IP must be given for retrieval')

###############################################
# Parse sends
def record_traffic(db, logdir):
	# Go through each log file and record what packets each host believes it sent
	for logName in glob('{}/*.log'.format(logdir)):
		# Determine what type of log this is. Alters parsing and processing
		name = os.path.basename(logName)
		name = name[:name.find('-')]

		isGate = name.startswith('gate')
		isProt = name.startswith('prot')
		isExt = name.startswith('ext')

		print('Processing log file for {}'.format(name))
		
		with open(logName) as log:
			if isGate:
				record_gate_admin_traffic(db, name, log)
			else:
				record_client_traffic(db, name, log) 

def record_client_traffic(db, name, log): 
	this_id = get_system(db, name=name)
	this_ip = None

	log.seek(0)
	c = db.cursor()

	# Record each packet this host saw
	count = 0
	log_line_num = 0
	c.execute('BEGIN TRANSACTION');
	for line in log:
		log_line_num += 1
		# Pull out data on each send or receive
		# Example lines:
		# 1351452800.14 LOG4 Sent 6:dd3f6ad25f9885796e1193fe93dd841e to 172.2.20.0:40869
		# 1351452800.14 LOG4 Received 6:33f773e74690b9dfe714f80d6e3d8c39 from 172.2.20.0:40869
		m = re.match('''^([0-9]+).*LOG[0-9] (Sent|Received) ([0-9]+):([a-z0-9]{{32}}) (?:to|from) ({}):(\d+)$'''.format(IP_REGEX), line)
		if m is None:
			continue

		time, direction, proto, hash, their_ip, port = m.groups()
		time = int(time)
		their_ip = inet_aton_integer(their_ip)
		their_id = get_system(db, ip=their_ip)

		if direction == 'Received':
			is_send = False
			src_ip = their_ip
			src_id = their_id
			dest_ip = this_ip
			dest_id = this_id
		else:
			is_send = True
			src_ip = this_ip
			src_id = this_id
			dest_ip = their_ip
			dest_id = their_id
		
		c.execute('''INSERT INTO packets (system_id, time, is_send, proto,
							src_ip, dest_ip, src_id, dest_id, hash, log_line)
						VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
						(this_id, time, is_send, proto,
							src_ip, dest_ip, src_id, dest_id, hash, log_line_num))

		count += 1
		if count % 1000 == 0:
			print('\tProcessed {} packets so far'.format(count))

	print('\t{} total packets processed'.format(count))
	db.commit()
	c.close()

def record_gate_admin_traffic(db, name, log):
	this_id = get_system(db, name=name)
	this_ip = None

	log.seek(0)
	c = db.cursor()

	admin_count = 1
	transform_count = 1
	log_line_num = 0
	c.execute('BEGIN TRANSACTION')
	for line in log:
		log_line_num += 1
		# transforms are handled later to ensure that all packets are in the system
		# Example lines:
		# 353608.535795917 LOG0 Outbound: Accept: Admin: sent: /p:253 s:172.2.196.104:0 d:172.1.113.38:0 hash:2f67e51d456961704b08f6ec186dd182
		# 353609.935773424 LOG0 Inbound: Accept: Admin: pong accepted: p:253 s:172.2.196.104:0 d:172.1.113.38:0 hash:9c05e526c46e5f4214f90201dd5e3b58/
		m = re.match('''^([0-9]+).*LOG[0-9] (Inbound|Outbound): (Accept|Reject): (Admin|NAT|Hopper): ([^:]+): (?:|{0})/(?:|{0})$'''.format(PACKET_ID_REGEX), line)
		if m is None:
			continue

		time, direction, result, module, reason = m.groups()[:5]
		in_proto, in_sip, in_sport, in_dip, in_dport, in_hash = m.groups()[5:11]
		out_proto, out_sip, out_sport, out_dip, out_dport, out_hash = m.groups()[11:]
		
		time = int(time)

		# We'll be recording the reason one way or another
		reason_id = add_reason(db, reason)

		# Create packets. A transformation line (IE, NAT or Hopper) may have both a send and 
		# receive. Admin lines will just be one or the other. Regardless, create both packets if
		# needed
		if in_sip is not None:
			is_send = False
			src_ip = inet_aton_integer(in_sip)
			src_id = get_system(db, ip=src_ip)
			dest_ip = inet_aton_integer(in_dip)
			dest_id = get_system(db, ip=dest_ip)
			hash = in_hash

			c.execute('''INSERT INTO packets (system_id, time, is_send, proto,
								src_ip, dest_ip, src_id, dest_id,
								hash, reason_id, log_line)
							VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
							(this_id, time, is_send, in_proto,
								src_ip, dest_ip, src_id, dest_id,
								hash, reason_id, log_line_num))
			in_packet_id = c.lastrowid
		else:
			in_packet_id = None

		if out_sip is not None:
			is_send = True
			src_ip = inet_aton_integer(out_sip)
			src_id = get_system(db, ip=src_ip)
			dest_ip = inet_aton_integer(out_dip)
			dest_id = get_system(db, ip=dest_ip)
			hash = out_hash

			c.execute('''INSERT INTO packets (system_id, time, is_send, proto,
								src_ip, dest_ip, src_id, dest_id,
								hash, reason_id, log_line)
							VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
							(this_id, time, is_send, out_proto,
								src_ip, dest_ip, src_id, dest_id,
								hash, reason_id, log_line_num))
			out_packet_id = c.lastrowid
		else:
			out_packet_id = None

		# If this was a transformation/a send in response to a receive, record the linkage
		if in_packet_id is not None and out_packet_id is not None:
			c.execute('UPDATE packets SET next_hop_id=? WHERE id=?', (out_packet_id, in_packet_id))
	
		# TBD, need to fix hashing, but then it would be nice to change the sent
		# packet (from the external) to point to the correct destination ID,
		# rather than the gate ID
		if module == 'NAT' and direction == 'Incoming':
			#c.execute('''UPDATE packets SET dest_id=? WHERE id=?''', (, ))
			pass

		if module == 'Admin':
			admin_count += 1
		else:
			transform_count += 1

		if admin_count % 1000 == 0:
			print('\t~{} admin packets processed'.format(admin_count))
		if transform_count % 1000 == 0:
			print('\t~{} transforms processed'.format(transform_count))
		
	print('\t{} total admin packets processed'.format(admin_count - 1))
	print('\t{} total transforms processed'.format(transform_count - 1))
	db.commit()
	c.close()

##########################################
# Track each sent packet through the system and determine either where it died or that
# it reached its destination
def trace_packets(db):
	print('Beginning packet trace')

	# Go one-by-one through packets and match them up
	packets = db.cursor()
	
	packets.execute('SELECT count(*) FROM packets WHERE is_send=1 AND next_hop_id IS NULL')
	total_count = packets.fetchone()[0]

	packets.execute('''SELECT system_id, id, time, hash, src_id, proto FROM packets
						WHERE is_send=1 AND next_hop_id IS NULL''')

	count = 0
	failed_count = 0
	for sent_packet in packets:
		system_id, packet_id, time, hash, src_id, proto = sent_packet

		# Find corresponding received packet
		c = db.cursor()
		c.execute('''SELECT id, next_hop_id FROM packets
						WHERE is_send=0 AND NOT id=?
							AND NOT system_id=?
							AND proto=?
							AND src_id=? AND hash=?
							AND time > ? AND time < ?
						ORDER BY next_hop_id DESC''',
						(packet_id, system_id, proto, src_id, hash, time - TIME_SLACK, time + TIME_SLACK))
		receives = c.fetchall()
		
		if len(receives) == 1:
			c.execute('UPDATE packets SET next_hop_id=? WHERE id=?', (receives[0][0], packet_id))

		elif len(receives) > 1:
			# Find the best match. We want a transformation if it exists. Actually,
			# if it doesn't freak out and die. We could put some knowledge like "protA1
			# should be using gateA as its next hop," but I don't think that's needed
			found = False
			for recv in receives:
				if recv[1] is not None:
					c.execute('UPDATE packets SET next_hop_id=? WHERE id=?', (recv[0], packet_id))
					found = True
					break

			if not found:
				print('Multiple possible receives found for packet {}'.format(packet_id))
				failed_count += 1

		else:
			# No matches found. We'll figure this one out later
			print('Unable to locate corresponding receive for packet {}'.format(packet_id))
			failed_count += 1

		c.close()

		count += 1
		if count % 1000 == 0:
			print('Tracing packet {} of {}'.format(count, total_count))

	print('{} traces attempted, {} failed'.format(count, failed_count))
	db.commit()
	packets.close()

def generate_stats(db, begin_time, end_time):
	print

########################################
# Helper utilities
def inet_aton_integer(ip):
	octets = ip.split('.')
	n = 0
	for o in octets:
		n = (n << 8) | int(o)
	return n

def inet_ntoa_integer(addr):
	ip = ''
	for i in range(0, 32, 8):
		ip = str(addr >> i & 0xFF) + '.' + ip
	return ip[:-1]

def get_time_limits(db):
	c = db.cursor()
	c.execute('SELECT time FROM packets ORDER BY time ASC LIMIT 1')
	beg = c.fetchone()[0]
	c.execute('SELECT time FROM packets ORDER BY time ASC LIMIT 1')
	end = c.fetchone()[0]
	c.close()
	return (beg, end)

def main(argv):
	# Parse command line
	parser = argparse.ArgumentParser(description='Process an ARG test network run')
	parser.add_argument('-l', '--logdir', default='.', help='Directory with pcap and log files from a test')
	parser.add_argument('-db', '--database', default=':memory:',
		help='SQLite database to save packet-tracing data to. If it already exists, \
			we assume it contains trace data. If not given, will be done in memory.')
	parser.add_argument('--empty-database', action='store_true', help='Empties the database if it already exists')
	parser.add_argument('-t', '--trace-only', action='store_true', help='Perform only the initial step of tracing each packet through the network. Do not pull stats out')
	parser.add_argument('--min-time', type=int, default=0, help='First moment in time to take stats from. Given in seconds relative to the start of the trace')
	parser.add_argument('--max-time', type=int, default=None, help='Latest packet time to account for in stats')
	args = parser.parse_args(argv[1:])

	# Ensure database is empty
	# If it is and/or if --empty-database was given, create the schema
	doTrace = True
	if os.path.exists(args.database):
		if args.empty_database:
			os.unlink(args.database)
		else:
			print('Database already exists, skipping packet trace.')
			print('To override this and force a new trace, give --empty-database on the command line\n')
			doTrace = False

	# Open database and create schema if it doesn't exist already
	db = sqlite3.connect(args.database)
	if doTrace:
		try:
			create_schema(db)
		except sqlite3.OperationalError as e:
			print("Unable to create database: ", e)
			return 1

	# Ensure all the systems are in place before we begin
	if doTrace:
		add_all_systems(db, args.logdir)

	# Trace packets
	if doTrace:
		# What did each host attempt to do?
		record_traffic(db, args.logdir)

		# Do quick check for packets making it to their destination
		trace_packets(db)
	
	if args.trace_only:
		print('Trace only requested. Processing complete')
		return 0

	# Collect stats
	# TBD allow packets outside of a range of times to be ignored
	generate_stats(db, args.min_time, args.max_time)

	# All done
	db.commit()
	db.close()

	return 0

if __name__ == '__main__':
	sys.exit(main(sys.argv))

