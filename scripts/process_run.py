#!/usr/bin/env python
from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division

import sys
import time
import os
import os.path
import sqlite3
import argparse
import re
import pcap
import scapy.all
import hashlib
from glob import glob

IP_REGEX='''(?:\d{1,3}\.){3}\d{1,3}'''
PACKET_ID_REGEX='''p:([0-9]+) s:({0}):([0-9]+) d:({0}):([0-9]+) hash:([a-z0-9]+)'''.format(IP_REGEX)

# Times on each host may not match up perfectly. How many second on either side do we allow?
TIME_SLACK=15
ROW_CACHE_SIZE=50000

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
	#	- time (float) - time in seconds, relative to the start of the experiment
	#	- is_send (bool)
	#	- is_valid (bool) - true if the sender believes this packet SHOULD reach its destination
	#			(ie, a spoofed packet may not be expected to work)
	#	- proto (int) - protocol of this packet
	#	- src_ip 
	#	- dest_ip
	#	- src_id (foreign: packet.id) - What host this packet is coming from (the sender of the packet)
	#	- dest_id (foreign: packet.id) - What host this packet is destined for next. Not teh final destination,
	#		the next routing stop
	#	- true_src_id (foreign: packet.id) - The ORIGINAL/real sender of this packet, before routing and transformations
	#	- true_dest_id (foreign: packet.id) - The REAL destination of this packet. IE, what host behind the gateways
	#	- hash (index) - MD5 hash of packet data, after the transport layer
	#	- next_hop_id (foreign: packet.id) - If this packet was transformed, then next_hop_id is the ID of the
	#		transformed packet. If this field is NULL on a sent packet, it was lost at this point and
	#		reason_id points to a description of why
	#	- terminal_hop_id  (foreign: packet.id) - The final packet in this trace. IE, if you followed
	#		next_hop_id until encountering a null, this id would be the packet you reached
	#	- trace_failed (bool) - True if the packet could not be traced (not received, probably)
	#	- truth_failed (bool) - True if the true source or destination of the packet could not be determined
	#	- reason_id (foreign: reseasons.id) - Text describing what happened with this packet
	#
	# settings
	#	- id (PK)
	#	- name (text) - Name of the setting
	#	- value (text) - Value of setting
	c = db.cursor()	
	c.execute('DROP TABLE IF EXISTS systems')
	c.execute('''CREATE TABLE systems (
						id INTEGER, name VARCHAR(25), ip INT, base_ip INT, mask INT,
						PRIMARY KEY(id ASC))''')
	
	c.execute('DROP TABLE IF EXISTS reasons')
	c.execute('''CREATE TABLE reasons (id INTEGER, msg VARCHAR(255),
						PRIMARY KEY(id ASC))''')
	
	c.execute('DROP TABLE IF EXISTS settings')
	c.execute('''CREATE TABLE IF NOT EXISTS settings (
						id INTEGER,
						name VARCHAR(20),
						value VARCHAR(20),
						PRIMARY KEY (id ASC))''')

	c.execute('DROP TABLE IF EXISTS packets')
	c.execute('''CREATE TABLE IF NOT EXISTS packets (
						id INTEGER,
						system_id INTEGER,
						log_line INT,
						pcap_log_line INT,
						time DOUBLE,
						is_send TINYINT DEFAULT NULL,
						is_valid TINYINT DEFAULT 1,
						proto SHORTINT,
						src_ip INT,
						dest_ip INT,
						src_id INT,
						dest_id INT,
						true_src_id INT,
						true_dest_id INT,
						full_hash CHARACTER(32),
						partial_hash CHARACTER(32),
						next_hop_id INT DEFAULT NULL,
						terminal_hop_id INT DEFAULT NULL,
						trace_failed TINYINT DEFAULT 0,
						truth_failed TINYINT DEFAULT 0,
						reason_id INT,
						PRIMARY KEY (id ASC))''')

	# After much experimentation, this combination of indexes proves effective. While
	# insert speeds are not impacted much by adding more indexes, the packet tracer updates
	# next_hop_id and trace_failed so often that having them indexed actually hurts things
	c.execute('''CREATE INDEX IF NOT EXISTS idx_full_hash ON packets (full_hash)''')
	c.execute('''CREATE INDEX IF NOT EXISTS idx_partial_hash ON packets (partial_hash)''')
	c.execute('''CREATE INDEX IF NOT EXISTS idx_system_id ON packets (system_id)''')
	#c.execute('''CREATE INDEX IF NOT EXISTS idx_src_id ON packets (src_id)''')
	#c.execute('''CREATE INDEX IF NOT EXISTS idx_dest_id ON packets (dest_id)''')
	c.execute('''CREATE INDEX IF NOT EXISTS idx_src_dest ON packets (src_id, dest_id)''')
	
	c.close()

def check_schema(db):
	valid_db = True

	try:
		c = db.cursor()

		c.execute('SELECT count(*) FROM packets')
		num = c.fetchone()[0]
		if num == 0:
			valid_db = False

		c.close()
	except sqlite3.OperationalError as e:
		valid_db = False

	return valid_db

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
# Manage settings table
def read_all_settings(db, logdir):
	# Clean slate
	c = db.cursor()
	c.execute('DELETE FROM settings')
	c.close()

	print('Reading in run settings')

	# Latency and test number comes from folder name
	dirname = os.path.basename(os.path.realpath(logdir))
	m = re.search('''-t([0-9]+)-l([0-9a-zA-Z]+)-''', dirname)
	if m is not None:
		add_setting(db, 'Test', m.group(1))
		add_setting(db, 'Latency', m.group(2))
	else:
		add_setting(db, 'Latency', 'unknown')

	# Read the settings for each log file
	for logName in glob(os.path.join(logdir, '*.log')):
		# Determine what type of log this is. Alters parsing and processing
		name = os.path.basename(logName)
		name = name[:name.find('-')]

		is_gate = name.startswith('gate')
		is_prot = name.startswith('prot')
		is_ext = name.startswith('ext')
		
		if not is_gate and not is_prot and not is_ext:
			continue
		
		if is_gate:
			# Only need to set hop rate setting once
			hr_set_name = '{} hop rate'.format(name)
			if get_setting(db, hr_set_name) is not None:
				continue

			m = re.search('''-hr([0-9]+ms)''', logName)
			if m is not None:
				add_setting(db, hr_set_name, m.group(1))
			else:
				add_setting(db, hr_set_name, 'unknown')
		else:
			if logName.find('send') == -1:
				m = re.search('''listen-(tcp|udp):([0-9]+)\.log''', logName)
				if m is not None:
					proto, port = m.groups()
					add_setting(db, '{} listener'.format(name), '{}, port {}'.format(proto, port))
				else:
					print('WARNING: Log file {} improperly named, unable to setup information')
			else:
				m = re.search('''send-(tcp|udp)-({}):([0-9]+)-delay:([0-9\.]+)\.log'''.format(IP_REGEX), logName)
				if m is not None:
					proto, ip, port, delay = m.groups()
					add_setting(db, '{} sender'.format(name), '{}, {}:{}, {} second delay'.format(proto, ip, port, delay))
				else:
					print('WARNING: Log file {} improperly named, unable to setup information')

def add_setting(db, name, value):
	c = db.cursor()
	try:
		c.execute('INSERT INTO settings (name, value) VALUES (?, ?)', (name, str(value)))
	except sqlite3.IntegrityError:
		c.execute('UPDATE settings SET value=? WHERE name=?', (str(value), name))
	c.close()

def get_setting(db, name):
	c = db.cursor()
	c.execute('SELECT id, value FROM settings WHERE name=?', (name,))
	result = c.fetchall()
	c.close()
	if result:
		return result
	else:
		return None

def show_settings(db):
	c = db.cursor()

	c.execute('SELECT length(name) FROM settings ORDER BY length(name) DESC LIMIT 1')
	width = c.fetchone()

	if width is not None:
		print('--- Run settings ---')

		outstr = '{:<' + str(width[0]) + '}: {}'

		c.execute('SELECT name, value FROM settings ORDER BY name ASC')
		for row in c:
			print(outstr.format(row[0], row[1]))
		c.close()

def get_test_number(db):
	c = db.cursor()
	c.execute('SELECT value FROM settings WHERE name="Test"')
	num = c.fetchone()
	c.close()

	if num is not None:
		return num[0]
	else:
		return None

def get_hop_rate(db):
	# Returns the hop rate(s) of the gates. If all of them are the same,
	# returns it as a singe number
	c = db.cursor()

	c.execute('SELECT value FROM settings WHERE name LIKE "%hop rate"')
	rates = [atoi(x[0]) for x in c.fetchall()]

	c.close()

	rates = list(set(rates))
	if len(rates) == 1:
		return rates[0]
	else:
		return rates

##############################################
# Manange system table
def add_all_systems(db, logdir):
	# Clean slate
	c = db.cursor()
	c.execute('DELETE FROM systems')
	c.close()

	print('Adding all systems to database')

	for logName in glob(os.path.join(logdir, '*.log')):
		# Determine what type of log this is. Alters parsing and processing
		name = os.path.basename(logName)
		name = name[:name.find('-')]

		is_gate = name.startswith('gate')
		is_prot = name.startswith('prot')
		is_ext = name.startswith('ext')

		print('\tFound {} with log {}'.format(name, logName))

		if not is_gate and not is_prot and not is_ext:
			continue
		
		with open(logName) as log:
			if is_gate:
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
	
	if ip is not None:
		add_system(db, name, ip)
	else:
		raise IOError('Unable to find IP for {} in log file'.format(name))

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

def check_systems(db):
	# Ensures that none of the assumptions regarding system naming are violated
	# IE, must be called either extX, gateX, or protXX. There may be only one prot
	# client behind each gateway. Each prot client must have a gateway with
	# their network (IE, protA1 has gateA)
	print('Checking systems for test setup problems')

	c = db.cursor()
	c.execute('SELECT name FROM systems')
	names = [name[0] for name in c.fetchall()]
	c.close()

	for name in names:
		if name.startswith('gate'):
			# Ensure it's properly formatted
			if re.match('gate[A-Z]', name) is None:
				print('Gates must be named "gateX," where X is a single capital letter')
				return False

		elif name.startswith('prot'):
			if re.match('prot[A-Z][0-9]', name) is None:
				print('Protected hosts must be named "protXY," where X is a capital letter and Y is a single digit 0-9')
				return False

			# There must be a gate with the same network "name" (the letter)
			gate_name = 'gate' + name[4]
			try:
				names.index(gate_name)
			except ValueError:
				print('There must be a corresponding gate for all protected clients')
				print('We have a {} but no {}'.format(name, gate_name))
				return False

		elif name.startswith('ext'):
			if re.match('ext[0-9]', name) is None:
				print('External hosts must be named "extX," where X is a single digit 0-9')
				return False

		else:
			print('All hosts on the network must be named "extX," "protXX," or "gateX"')
			return False
	
	print('Everything appears fine')
	return True

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
		raise Exception('Name, ID, or IP must be given for retrieval')

###############################################
# Parse sends
def record_traffic_pcap(db, logdir):
	# Ensure we don't double up packet data or something silly like that
	c = db.cursor()
	c.execute('DELETE FROM packets')

	c.execute('BEGIN TRANSACTION')

	# Go through each log file and record what packets each host sent
	for logName in glob(os.path.join(logdir, '*.pcap')):
		# Determine who this log belongs to
		name = os.path.basename(logName)

		m = re.match('^([a-zA-Z0-9]+?)(?:|-(inner|outer))\.', name)
		if m is None:
			raise Exception('Unable to get name from {}'.format(name))
		name = m.group(1)

		is_inner_log = (m.group(2) == 'inner')

		is_gate = name.startswith('gate')
		is_prot = name.startswith('prot')
		is_ext = name.startswith('ext')

		if not is_gate and not is_prot and not is_ext:
			continue

		if not is_ext:
			network = name[4]

		if is_gate:
			prot_client_id = get_system(db, name='prot{}1'.format(network))
		elif is_prot:
			gate_id = get_system(db, name='gate{}'.format(network))

		print('Processing pcap file {} for {}'.format(logName, name))
		
		p = pcap.pcapObject()
		p.open_offline(logName.encode('utf-8'))

		# Grab the system ID for this log
		system_id = get_system(db, name=name)
		if system_id is None:
			print('\tSkipping, this system is not in the database. There were likely no log files')
			continue

		system_ip = get_system(db, id=system_id)

		pcap_count = 0
		count = 0
		while True:
			packet = p.next()
			if packet is None:
				break

			data, time = packet[1:]
			pcap_count += 1
			packet = scapy.all.Ether(data)

			# Skip packets we don't care about
			if not packet.haslayer(scapy.layers.inet.IP):
				continue

			# Hashes
			full_hash, partial_hash = md5_packet(packet)

			# Who is this packet to and from?
			ip_layer = packet.getlayer(scapy.layers.inet.IP)
			src_ip = inet_aton_integer(ip_layer.src)
			dest_ip = inet_aton_integer(ip_layer.dst)

			src_id = get_system(db, ip=src_ip)
			dest_id = get_system(db, ip=dest_ip)

			# Direction? NOTE: is_send may be None, indicating we don't know
			# We use this to help determine the src_id and dest_id, which are
			# the next system this packet should hit (rather than the ID that the
			# IP indicates, which may not be what we went)
			if src_id == system_id:
				is_send = True
			elif dest_id == system_id:
				is_send = False
			elif is_gate and is_inner_log:
				# Use our knowledge of the network to determine direction.
				# For the inner log, packets from the prot client are receives.
				if src_id == prot_client_id:
					is_send = False
				else:
					is_send = True
			else:
				# Unable to tell
				print('Unable to tell direction of packet with full hash {}, pcap line {}'.format(full_hash, pcap_count))
				is_send = None

			# Determine who the next system to see this packet should be
			if is_prot:
				# Protected clients actually have to jump through the gate,
				# that's the first destination for their packets
				if is_send == True:
					dest_id = gate_id
				elif is_send == False:
					src_id = gate_id	
			elif is_ext:
				# External clients must send their packets through the gate of
				# the correct network. Fortunately for us, that's already taken care
				# of. However, TBD make SURE the gate ID is chosen. If the packet
				# happens to use the protected client's IP, that won't be true
				pass
			else:
				if is_inner_log:
					if is_send == True:
						# Gate sending to the inside must be shooting for it's client and the packet
						# comes from us
						dest_id = prot_client_id
						src_id = system_id
					elif is_send == False:
						# Gate receiving on inside must be from protected and going through us
						dest_id = system_id
						src_id = prot_client_id
				else:
					if is_send == True:
						# Gate sending out already has the correct dest_id, but the source is us
						# no matter what. Really, this is probably already true from above, but
						# if that logic changes this fact will still hold true
						src_id = system_id
					elif is_send == False:
						dest_id = system_id

			# Insert it
			c.execute('''INSERT INTO packets (system_id, time, pcap_log_line,
								proto, src_ip, dest_ip, src_id, dest_id,
								full_hash, partial_hash)
							VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
							(system_id, time, pcap_count, ip_layer.proto,
								src_ip, dest_ip, src_id, dest_id,
								full_hash, partial_hash,))

			count += 1
			if count % 1000 == 0:
				print('\tProcessed {} packets so far'.format(count))

		print('\t{} total packets processed'.format(count))

	db.commit()
	c.close()

def record_traffic_logs(db, logdir):
	# Go through each log files and record what packets each host believes it sent
	# Use this information to augment what we pulled from the pcap logs earlier
	for logName in glob(os.path.join(logdir, '*.log')):
		# Determine what type of log this is. Alters parsing and processing
		name = os.path.basename(logName)
		name = name[:name.find('-')]

		is_gate = name.startswith('gate')
		is_prot = name.startswith('prot')
		is_ext = name.startswith('ext')

		if not is_gate and not is_prot and not is_ext:
			continue

		print('Processing log file {} for {}'.format(logName, name))
		
		with open(logName) as log:
 			if is_gate:
				record_gate_traffic_log(db, name, log)
 			else:
				record_client_traffic_log(db, name, log) 

def record_client_traffic_log(db, name, log): 
	this_id = get_system(db, name=name)
	this_ip = None

	is_prot = name.startswith('prot')
	is_ext = name.startswith('ext')
	if is_prot:
		network = name[4]
		gate_id = get_system(db, name='gate'+network)

	log.seek(0)
	c = db.cursor()

	# Record each packet this host saw
	count = 0
	log_line_num = 0

	client_re = re.compile('''^(\d+(?:|\.\d+)) LOG[0-9] (Sent|Received) (valid|invalid) ([0-9]+):([a-z0-9]{{32}}) (?:to|from) ({}):(\d+)$'''.format(IP_REGEX))

	c.execute('BEGIN TRANSACTION')

	for line in log:
		log_line_num += 1
		# Pull out data on each send or receive
		# Example lines:
		# 1351452800.14 LOG4 Sent 6:dd3f6ad25f9885796e1193fe93dd841e to 172.2.20.0:40869
		# 1351452800.14 LOG4 Received 6:33f773e74690b9dfe714f80d6e3d8c39 from 172.2.20.0:40869
		m = client_re.match(line)
		if m is None:
			continue

		time, direction, valid, proto, partial_hash, their_ip, port = m.groups()
		time = float(time)
		is_valid = (valid == 'valid')
		their_ip = inet_aton_integer(their_ip)
		their_id = get_system(db, ip=their_ip)

		if direction == 'Received':
			is_send = False

			dest_ip = this_ip
			dest_id = this_id
			true_dest_id = this_id

			src_ip = their_ip

			if is_prot:
				# For a protected client, a received packet always has the real
				# src and destination IPs. The previous routing location was the gateway though
				src_id = gate_id
				true_src_id = their_id
			else:
				# For an external client, a received packet must be coming from the gateway
				# However, we don't actually know the gateway, but their_id is more than likely correct
				# The gateway IP would have to match the internal client for that to not be true,
				# which is a 1 in 65536 chance. TBD, could create a get_system_gate(db, ip)
				# We don't know the true sender yet
				src_id = their_id

				gate_name = get_system(db, id=src_id)[2]
				true_src_id = get_system(db, name='prot{}1'.format(gate_name[4]))
		else: 
			is_send = True

			src_ip = this_ip
			src_id = this_id
			true_src_id = this_id

			dest_ip = their_ip

			if is_prot:
				# A protected client knows the true destination of packets it sends
				# The next hop must be a gateway
				dest_id = gate_id
				true_dest_id = their_id
			else:
				# An external client doesn't actually know the interal client's ID, but
				# we require (for the test) that there's only one of them and we know the 
				# network they're on, so...
				dest_id = their_id

				gate_name = get_system(db, id=dest_id)[2]
				true_dest_id = get_system(db, name='prot{}1'.format(gate_name[4]))

		c.execute('''UPDATE packets SET is_send=?, is_valid=?,
							true_src_id=?, true_dest_id=?, log_line=?
						WHERE system_id=? AND partial_hash=?''',
						(is_send, is_valid,
							true_src_id, true_dest_id, log_line_num,
							this_id, partial_hash))

		count += 1
		if count % 1000 == 0:
			print('\tProcessed {} packets so far'.format(count))

	print('\t{} total packets processed'.format(count))
	db.commit()
	c.close()

def record_gate_traffic_log(db, name, log):
	this_id = get_system(db, name=name)
	this_ip = None
	network = name[4]
	prot_id = get_system(db, name='prot{}1'.format(network))

	log.seek(0)
	c = db.cursor()

	admin_count = 1
	transform_count = 1
	log_line_num = 0
	
	gate_re = re.compile('''^(\d+(?:|\.\d+)) LOG[0-9] (Inbound|Outbound): (Accept|Reject): (Admin|NAT|Hopper): ([^:]+): (?:|{0})/(?:|{0})$'''.format(PACKET_ID_REGEX))

	c.execute('BEGIN TRANSACTION')

	for line in log:
		log_line_num += 1
		# Example lines:
		# 353608.535795917 LOG0 Outbound: Accept: Admin: sent: /p:253 s:172.2.196.104:0 d:172.1.113.38:0 hash:2f67e51d456961704b08f6ec186dd182
		# 353609.935773424 LOG0 Inbound: Accept: Admin: pong accepted: p:253 s:172.2.196.104:0 d:172.1.113.38:0 hash:9c05e526c46e5f4214f90201dd5e3b58/
		m = gate_re.match(line)
		if m is None:
			continue

		time, direction, result, module, reason = m.groups()[:5]
		in_proto, in_sip, in_sport, in_dip, in_dport, in_full_hash = m.groups()[5:11]
		out_proto, out_sip, out_sport, out_dip, out_dport, out_full_hash = m.groups()[11:]
		
		time = float(time)

		# We'll be recording the reason one way or another
		reason_id = add_reason(db, '{} {}'.format(direction, reason))

		# Create packets. A transformation line (IE, NAT or Hopper) may have both a send and 
		# receive. Admin lines will just be one or the other. Regardless, create both packets if
		# needed
		if in_sip is not None:
			is_send = False

			src_ip = inet_aton_integer(in_sip)
			src_id = get_system(db, ip=src_ip)
			true_src_id = None

			dest_ip = inet_aton_integer(in_dip)
			dest_id = this_id
			true_dest_id = None

			full_hash = in_full_hash

			if direction == 'Outbound':
				# For an outbound receive, this packet must have come from a protected client
				# We therefore know the real destination and source. Easy!
				true_src_id = src_id
				true_dest_id = get_system(db, ip=dest_ip)
			else:
				# For an inbound receive, the packet may have come from either an external
				# client or the other gateway. For the other gateway, we know the it could be an
				# admin packet or it could be a wrapped packet. For admin we have all the information we need.
				# For wrapped, we need to look at the send (assuming we have one) to determine the true
				# source and destination. For an external client we have the true source but an
				# incomplete destination. However, we can get the true destination if we actually
				# forwarded the packet.
				if module == 'Admin':
					true_src_id = src_id
					true_dest_id = this_id
					
				else:
					if out_sip is not None:
						true_src_id = get_system(db, ip=inet_aton_integer(out_sip))
						true_dest_id = get_system(db, ip=inet_aton_integer(out_dip))

			c.execute('''SELECT id FROM packets WHERE system_id=? AND full_hash=?''', (this_id, full_hash))
			in_packet_id = c.fetchone()
			if in_packet_id is not None:
				in_packet_id = in_packet_id[0]
				c.execute('''UPDATE packets SET log_line=?, reason_id=?, is_send=?,
								true_src_id=?, true_dest_id=? WHERE id=?''',
								(log_line_num, reason_id, is_send,
									true_src_id, true_dest_id,
									in_packet_id))
			else:
				print('Unable to find match for inbound packet with full hash {}, line {}'.format(full_hash, log_line_num))
		else:
			in_packet_id = None

		if out_sip is not None:
			is_send = True

			src_ip = inet_aton_integer(out_sip)
			src_id = this_id
			true_src_id = None

			dest_ip = inet_aton_integer(out_dip)
			dest_id = get_system(db, ip=dest_ip)
			true_dest_id = None

			full_hash = out_full_hash

			if direction == 'Outbound':
				if module == 'Admin':
					# Straight forward enough, we're sending an admin packet to another gate
					true_src_id = this_id
					true_dest_id = dest_id

				else:
					# True source and destination can be deduced through what we
					# received, as that prompted this send
					if in_sip is not None:
						true_src_id = get_system(db, ip=inet_aton_integer(in_sip))
						true_dest_id = get_system(db, ip=inet_aton_integer(in_dip))

			else:
				if module == 'Admin':
					true_src_id = this_id
					true_dest_id = dest_id

				else:
					true_src_id = get_system(db, ip=src_ip)
					true_dest_id = dest_id

			c.execute('''SELECT id FROM packets WHERE system_id=? AND full_hash=?''', (this_id, full_hash))
			out_packet_id = c.fetchone()
			if out_packet_id is not None:
				out_packet_id = out_packet_id[0]
				c.execute('''UPDATE packets SET log_line=?, reason_id=?, is_send=?,
								true_src_id=?, true_dest_id=? WHERE id=?''',
								(log_line_num, reason_id, is_send,
									true_src_id, true_dest_id,
									out_packet_id))
			else:
				print('Unable to find match for outbound packet with full hash {}, line {}'.format(full_hash, log_line_num))
		else:
			out_packet_id = None

		# If this was a transformation/a send in response to a receive, record the linkage
		if in_packet_id is not None and out_packet_id is not None:
			c.execute('UPDATE packets SET next_hop_id=? WHERE id=?', (out_packet_id, in_packet_id))

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
	c = db.cursor()
	c.execute('BEGIN TRANSACTION')
	
	c.execute('SELECT count(*) FROM packets WHERE is_send=1 AND next_hop_id IS NULL')
	total_count = c.fetchone()[0]

	hopless_packets = list()
	curr_packet = len(hopless_packets)

	count = 0
	failed_count = 0
	start_time = time.time()
	while True:
		if curr_packet >= len(hopless_packets):
			print('\tGrabbing packets that need processing')
			c.execute('''SELECT system_id, id, time, full_hash, src_id, dest_id, proto FROM packets
							WHERE is_send=1
								AND trace_failed=0
								AND next_hop_id IS NULL
							LIMIT ?''', (ROW_CACHE_SIZE,))
			hopless_packets = c.fetchall()
			curr_packet = 0

			# If we're all out of packets, terminate
			if not hopless_packets:
				break

		sent_packet = hopless_packets[curr_packet]
		curr_packet += 1
		system_id, packet_id, packet_time, full_hash, src_id, dest_id, proto = sent_packet

		# Find corresponding received packet
		c.execute('''SELECT id, next_hop_id, system_id FROM packets
						WHERE is_send=0
							AND NOT system_id=?
							AND src_id=? AND dest_id=?
							AND full_hash=?
							AND NOT id=?
							AND proto=?
							AND time > ? AND time < ?
						ORDER BY next_hop_id DESC, id ASC''',
						(system_id, src_id, dest_id, 
							full_hash, packet_id,
							proto,
							packet_time - TIME_SLACK, packet_time + TIME_SLACK))
		receives = c.fetchall()
		
		if len(receives) == 1:
			c.execute('UPDATE packets SET next_hop_id=? WHERE id=?', (receives[0][0], packet_id))

		elif len(receives) > 1:
			# Ensure all systems are the same. If they, are this, is almost certainly a retransmission
			# If they aren't, we have a problem
			print('Multiple receives matched sent packet {}, this is likely a retransmission.'.format(packet_id))
			sys = receives[0][2]
			for recv in receives:
				if recv[2] != sys:
					print('Found multiple systems with the same receive... this is a problem (not a retransmission?)')
					break

			next_hop = receives[0][0]
			print('Picked {} as the matching receive'.format(next_hop))
			c.execute('UPDATE packets SET next_hop_id=? WHERE id=?', (next_hop, packet_id))

		else:
			# No matches found. We'll figure this one out later
			#print('Unable to locate corresponding receive for packet {}'.format(packet_id))
			c.execute('UPDATE packets SET trace_failed=1 WHERE id=?', (packet_id,))
			failed_count += 1

		count += 1
		if count % 500 == 0:
			time_per_chunk = time.time() - start_time
			start_time = time.time()
			print('\tTracing packet {} of {} (~{:.1f} minutes remaining, {:.1f} seconds per 500)'.format(
				count, total_count, (total_count - count) / 500 * time_per_chunk / 60, time_per_chunk))

			db.commit()
			c.execute('BEGIN TRANSACTION')

	db.commit()

	if count > 0:
		print('\t{} traces attempted, {} failed'.format(count, failed_count))
	else:
		print('\tEverything appears to be in order here. No traces needed')

	# Add next_hop_id index now that all the data is ready
	print('Creating index for routing data')
	c.execute('''CREATE INDEX IF NOT EXISTS idx_next_id ON packets (next_hop_id)''')
	
	db.commit()
	c.close()

def complete_packet_intentions(db):
	# Find any packets that don't know their true source or destination, find
	# the beginning of the trace they are a part of, and run through it trying to
	# find data to fill it in
	print('Finalizing true packet intentions')

	missing = db.cursor()
	missing.execute('''SELECT id, true_src_id, true_dest_id
						FROM packets
						WHERE truth_failed=0
							AND (true_src_id IS NULL OR true_dest_id IS NULL)''')


	count = 0
	for row in missing:
		packet_id = row[0]
		
		# Find the beginning of this trace
		c = db.cursor()
		curr_id = packet_id
		print('On packet {}'.format(packet_id))
		while True:
			c.execute('SELECT id FROM packets WHERE next_hop_id=?', (curr_id,))
			prev_id = c.fetchone()
			if prev_id is None:
				break

			curr_id = prev_id[0]
			print('Digging into {}'.format(curr_id))

		# Run down this trace to find the true source and dest
		true_src_id = row[1]
		true_dest_id = row[2]

		src_found = False
		dest_found = False

		while curr_id is not None and (true_src_id is None or true_dest_id is None):
			c.execute('''SELECT next_hop_id, true_src_id, true_dest_id 
							FROM packets
							WHERE id=?''', (curr_id,))
			next_id, src, dest = c.fetchone()
			
			if src is not None:
				if true_src_id is None:
					src_found = True
					true_src_id = src
				elif true_src_id != src:
					raise Exception('Problem! Packet {} has a different true source than {} but is in the same trace'.format(packet_id, curr_id))

			if dest is not None:
				if true_dest_id is None:
					dest_found = True
					true_dest_id = dest
				elif true_dest_id != dest:
					raise Exception('Problem! Packet {} has a different true dest than {} but is in the same trace'.format(packet_id, curr_id))

			curr_id = next_id

		# Fix what we can
		if src_found or dest_found:
			c.execute('UPDATE packets SET true_src_id=?, true_dest_id=? WHERE id=?', (true_src_id, true_dest_id, packet_id))
		else:
			c.execute('UPDATE packets SET truth_failed=1 WHERE id=?', (packet_id,))

		db.commit()
		c.close()

		count += 1
		if count % 1000 == 0:
			print('\tFinalizing packet {}'.format(count))
	
	db.commit()
	missing.close()

	if count > 0:
		print('\t{} packets finalized'.format(count))
	else:
		print('\tNo work needed')

def locate_trace_terminations(db):
	print('Determining terminal packet of all traces')

	# Terminal packets terminate at themselves, take care of that first
	c = db.cursor()
	c.execute('BEGIN TRANSACTION')
	c.execute('UPDATE packets SET terminal_hop_id=id WHERE next_hop_id IS NULL')

	c.execute('''SELECT count(*) FROM packets
					WHERE next_hop_id IS NOT NULL
						AND terminal_hop_id IS NULL''')
	total_count = c.fetchone()[0]

	# For each packet that doesn't know its terminator, hop forward until we find one
	# Start at the end of traces (roughly) so that later packets find the terminal faster
	unterminated_packets = list()
	curr_packet = len(unterminated_packets)

	count = 0

	while True:
		if curr_packet >= len(unterminated_packets):
			print('\tGrabbing packets that need processing')
			c.execute('''SELECT id, next_hop_id FROM packets
									WHERE next_hop_id IS NOT NULL
										AND terminal_hop_id IS NULL
									ORDER BY id DESC
									LIMIT ?''', (ROW_CACHE_SIZE,))
			unterminated_packets = c.fetchall()
			curr_packet = 0

			# If we're all out of packets, terminate
			if not unterminated_packets:
				break

		curr_id, next_hop = unterminated_packets[curr_packet]
		curr_packet += 1

		# Loop forward until we find a packet that has terminal_hop_id set
		while True:
			c.execute('''SELECT next_hop_id, terminal_hop_id FROM packets WHERE id=?''', (next_hop,))
			next_hop, next_terminal = c.fetchone()

			if next_terminal is not None:
				c.execute('''UPDATE packets SET terminal_hop_id=? WHERE id=?''', (next_terminal, curr_id))
				break
			elif next_hop is None:
				raise Exception('Reached end of trace without finding terminal packet. This should not be possible')

		# Status update
		count += 1
		if count % 1000 == 0:
			print('\tTerminated {} packets of {}'.format(count, total_count))
			db.commit()
			c.execute('BEGIN TRANSACTION')

	db.commit()
	c.close()

	if count > 0:
		print('\tTerminated {} packets total'.format(count, total_count))
	else:
		print('\tNothing to be done')

def check_for_trace_cycles(db):
	print('Checking for cycles in packet traces: ')
	bad = for_all_traces(db, check_trace)
	if bad:
		print('\tCycles found for packet IDs {}'.format(bad))
	else:
		print('\tNo cycles found')
	return bad

def show_all_traces(db):
	for_all_traces(db, show_trace)
	
def check_trace(db, packet_id, cycle_limit=10):
	c = db.cursor()

	curr_id = packet_id
	is_send = True

	cycles = 0
	while curr_id is not None and cycles < cycle_limit:
		c.execute('''SELECT next_hop_id FROM packets WHERE id=?''', (curr_id,))
		row = c.fetchone()
		if row is None:
			break

		cycles += 1
		curr_id = row[0]
	
	c.close()
	
	return cycles < cycle_limit

def show_trace(db, packet_id, cycle_limit=10):
	desc = 'Trace of packet {}: '.format(packet_id)

	c = db.cursor()

	curr_id = packet_id
	is_send = True

	cycles = 0
	while curr_id is not None and cycles < cycle_limit:
		c.execute('''SELECT is_send, full_hash, next_hop_id FROM packets WHERE id=?''', (curr_id,))
		row = c.fetchone()
		if row is None:
			break

		if cycles != 0 and cycles % 2 == 0:
			desc += '\n' + ' '*(desc.find(':') - 1) + '-> '
		cycles += 1

		is_send, full_hash, next_hop_id = row
		desc += '{}:{} -> '.format(curr_id, full_hash)

		curr_id = next_hop_id
	
	# If the last packet we saw was a send, warn of the break in the chain (never saw a receive)
	if is_send:
		desc += '(not received)'
	else:
		desc = desc[:-3]

	c.close()
	
	if cycles >= cycle_limit:
		desc += '(cycle limit reached, not done)'
	
	print(desc)

	return cycles < cycle_limit

def for_all_traces(db, callback):
	c = db.cursor()
	c.execute('''SELECT l.id, r.next_hop_id AS rhop
						FROM packets AS l
						LEFT OUTER JOIN packets AS r ON l.id = r.next_hop_id
					WHERE l.is_send=1
						AND rhop IS NULL ''')
	failures = list()
	for row in c:
		if not callback(db, row[0]):
			failures.append(row[0])
	
	c.close()

	return failures

def atoi(a):
	i = 0
	while a:
		try:
			i = int(a)
			break
		except:
			a = a[:-1]

	return i

########################################
# Collect results and stats!
def generate_stats(db, begin_time_buffer=None, end_time_buffer=None):
	c = db.cursor()

	stats = {}

	# Get the absolute (rather than relative) times to generate stats on
	c.execute('SELECT time FROM packets ORDER BY time ASC LIMIT 1')
	abs_begin_time = c.fetchone()[0]
	if begin_time_buffer is not None:
		abs_begin_time += begin_time_buffer
	
	c.execute('SELECT time FROM packets ORDER BY time DESC LIMIT 1')
	abs_end_time = c.fetchone()[0]
	if end_time_buffer is not None:
		abs_end_time -= end_time_buffer
	
	stats['time.begin'] = abs_begin_time
	stats['time.end'] = abs_end_time
	stats['time.total'] = abs_end_time - abs_begin_time

	# Trace problems
	c.execute('''SELECT sum(trace_failed), sum(truth_failed) FROM packets
					WHERE time BETWEEN ? AND ?''', (abs_begin_time, abs_end_time))
	failed_trace_count, failed_truth_count = c.fetchone()
	stats['failed.traces'] = failed_trace_count
	stats['failed.truth'] = failed_truth_count

	# Valid sends vs receives (loss rate)
	loss_rate, sent_count, receive_count, lost_packets = valid_loss_rate(db, abs_begin_time, abs_end_time)
	stats['valid.sent'] = sent_count
	stats['valid.recv'] = receive_count
	stats['valid.loss.rate'] = loss_rate
	stats['valid.loss.examples'] = lost_packets

	loss_rate, sent_count, receive_count, not_lost_packets = invalid_loss_rate(db, abs_begin_time, abs_end_time)
	stats['invalid.sent'] = sent_count
	stats['invalid.recv'] = receive_count
	stats['invalid.loss.rate'] = loss_rate
	stats['invalid.recvd.examples'] = not_lost_packets

	# Rejection methods (for every packet that didn't make it to its destination, why
	# did it fail?)
	losses = loss_methods(db, abs_begin_time, abs_end_time)
	
	# Latency introduced by ARG
	avgs = avg_latency(db, abs_begin_time, abs_end_time)
	stats['latency.overall'] = avgs[0]
	stats['latency.nat'] = avgs[1]
	stats['latency.wrapped'] = avgs[2]

	c.close()

	return (stats, losses)

def print_stats(db, begin_time_buffer=None, end_time_buffer=None):
	stats, losses = generate_stats(db, begin_time_buffer, end_time_buffer)

	print('--- Statistics ---')
	print('Generating statistics for time {:.1f} to {:.1f} ({:.2f} seconds total)'.format(
		stats['time.begin'], stats['time.end'], stats['time.total']))
	print('Failed traces (unable to find a corresponding receive): {} packets'.format(stats['failed.traces']))
	print('Failed truth determinations (unable to find intended source or destination): {} packets'.format(stats['failed.truth']))

	print('\nValid packets sent: {}'.format(stats['valid.sent']))
	print('Valid packets received: {}'.format(stats['valid.recv']))
	print('Valid packets lost: {} ({})'.format(stats['valid.sent'] - stats['valid.recv'], stats['valid.loss.examples'][:10]))
	print('Valid packet loss rate: {}'.format(stats['valid.loss.rate']))

	print('\nInvalid packets sent: {}'.format(stats['invalid.sent']))
	print('Invalid packets received: {} ({})'.format(stats['invalid.recv'], stats['invalid.recvd.examples'][:10]))
	print('Invalid packets lost: {}'.format(stats['invalid.sent'] - stats['invalid.recv']))
	print('Invalid packet loss rate: {}'.format(stats['invalid.loss.rate']))

	print('\nLosses:')
	for msg, packets in losses.iteritems():
		print('  {}: {} packets ({})'.format(msg, len(packets), packets[:10]))

	print('\nAverage packet latency: (take with a grain of salt)')
	print('Overall average: {:.1f} ms'.format(stats['latency.overall']))
	print('NATed average: {:.1f} ms'.format(stats['latency.nat']))
	print('Wrapped average: {:.1f} ms'.format(stats['latency.wrapped']))

def valid_loss_rate(db, begin, end):
	# Compare the number of sent valid packets to the number of sent valid packets
	# that actually reached their intended destination (ideally 0)
	c = db.cursor()
	c.execute('''SELECT p1.id FROM packets AS p1 
					JOIN systems ON system_id=systems.id
					WHERE name NOT LIKE 'gate%'
						AND is_send=1
						AND is_valid=1
						AND time BETWEEN ? AND ?''', (begin, end))	
	sent = c.fetchall()
	send_count = len(sent)

	c.execute('''SELECT p1.id FROM packets AS p1
					JOIN systems ON p1.system_id=systems.id
					JOIN packets AS p2 ON p1.terminal_hop_id=p2.id
					WHERE name NOT LIKE 'gate%'
						AND p1.true_dest_id=p2.system_id
						AND p1.is_send=1
						AND p1.is_valid=1
						AND p1.time BETWEEN ? AND ?''', (begin, end))	
	recvd = c.fetchall()
	recv_count = len(recvd)

	c.close()

	# Get the IDs of the packets we lost
	lost = [x[0] for x in set(sent) - set(recvd)]
	
	if send_count > 0:
		return ((send_count - recv_count)/send_count, send_count, recv_count, lost)
	else:
		return (0, 0, 0, [])

def invalid_loss_rate(db, begin, end):
	# Compare the number of sent _invalid_ packets to the number of sent invalid packets
	# that actually reached their intended destination (ideally 100%)
	c = db.cursor()
	c.execute('''SELECT p1.id FROM packets AS p1
					JOIN systems ON system_id=systems.id
					WHERE name NOT LIKE 'gate%'
						AND is_send=1
						AND is_valid=0
						AND time BETWEEN ? AND ?''', (begin, end))	
	sent = c.fetchall()
	send_count = len(sent)
	
	c.execute('''SELECT p1.id FROM packets AS p1
					JOIN systems ON p1.system_id=systems.id
					JOIN packets AS p2 ON p1.terminal_hop_id=p2.id
					WHERE name NOT LIKE 'gate%'
						AND p1.true_dest_id=p2.system_id
						AND p1.is_send=1
						AND p1.is_valid=0
						AND p1.time BETWEEN ? AND ?''', (begin, end))	
	recvd = c.fetchall()
	recv_count = len(recvd)
	c.close()

	# Get the IDs of the packets we DIDN'T lose
	not_lost = [x[0] for x in recvd]

	if send_count > 0:
		return ((send_count - recv_count)/send_count, send_count, recv_count, not_lost)
	else:
		return (1, 0, 0, [])

def loss_methods(db, begin, end):
	# Get sent packets that didn't make it to their destination
	c = db.cursor()
	c.execute('''SELECT p1.id, msg, p2.next_hop_id, systems.name FROM packets AS p1
					JOIN packets AS p2 ON p1.terminal_hop_id=p2.id
					LEFT OUTER JOIN reasons ON reasons.id=p2.reason_id
					JOIN systems ON p2.system_id=systems.id
					WHERE p1.is_send=1
						AND (p1.true_dest_id IS NULL OR NOT p1.true_dest_id=p2.system_id)
						AND p1.time BETWEEN ? AND ?''', (begin, end))
	
	packet_cats = {'Unknown': list()}
	for row in c:
		packet_id, reason_msg, next_hop_id, name = row
		is_gate = name.startswith('gate')
		is_prot = name.startswith('prot')
		is_ext = name.startswith('ext')

		# The gate was the last place to see the packet. However, if it forwarded it,
		# then we don't want to blame them... file it under "unknown"
		if reason_msg is not None:
			try:
				packet_cats[reason_msg].append(packet_id)
			except KeyError:
				packet_cats[reason_msg] = [packet_id,]
		else:
			packet_cats['Unknown'].append(packet_id)

	c.close()
	return packet_cats

def avg_latency(db, begin, end):
	# Get the average latency for packets that passed through the NAT
	# and packets that were wrapped. ASSUMES NODES ARE CONNECTED DIRECTLY
	# TO GATES!
	c = db.cursor()
	c.execute('''SELECT AVG(p2.time - p1.time) AS latency FROM packets AS p1
					JOIN packets AS p2 ON p1.terminal_hop_id=p2.id
					JOIN systems ON p1.system_id=systems.id
					WHERE name NOT LIKE 'gate%'
						AND p1.true_dest_id=p2.system_id
						AND p1.is_send=1
						AND p1.is_valid=1
						AND p1.time BETWEEN ? AND ?''', (begin, end))	
	overall = c.fetchone()[0]
	if overall is None:
		overall = 0

	c.execute('''SELECT AVG(p2.time - p1.time) AS latency FROM packets AS p1
					JOIN packets AS p2 ON p1.terminal_hop_id=p2.id
					JOIN packets AS np ON p1.next_hop_id=np.id
					JOIN reasons ON np.reason_id=reasons.id
					JOIN systems ON p1.system_id=systems.id
					WHERE name NOT LIKE 'gate%'
						AND reasons.msg LIKE '%rewrite'
						AND p1.true_dest_id=p2.system_id
						AND p1.is_send=1
						AND p1.is_valid=1
						AND p1.time BETWEEN ? AND ?''', (begin, end))	
	nat = c.fetchone()[0]
	if nat is None:
		nat = 0

	c.execute('''SELECT AVG(p2.time - p1.time) AS latency FROM packets AS p1
					JOIN packets AS p2 ON p1.terminal_hop_id=p2.id
					JOIN packets AS np ON p1.next_hop_id=np.id
					JOIN reasons ON np.reason_id=reasons.id
					JOIN systems ON p1.system_id=systems.id
					WHERE name NOT LIKE 'gate%'
						AND reasons.msg LIKE '%wrapped'
						AND p1.true_dest_id=p2.system_id
						AND p1.is_send=1
						AND p1.is_valid=1
						AND p1.time BETWEEN ? AND ?''', (begin, end))	
	hopper = c.fetchone()[0]
	if hopper is None:
		hopper = 0
	c.close()

	return [x*1000 for x in (overall, nat, hopper)]
	
########################################
# Helpers
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

def print_raw(string):
	# Prints the raw bytes of a string in hex
	curr = 0
	for c in string:
		if curr % 16 == 0:
			print('{:0>4x}   '.format(curr), end='')

		print('{:0>2x} '.format(ord(c)), end='')

		curr += 1
		if curr % 16 == 0:
			print()
		elif curr % 8 == 0:
			print(' ', end='')

	if curr % 16 != 0:
		print()

def md5_packet(pkt):
	# Returns both md5 of the full packet from the IP layer down,
	# excluding the checksums at each layer. Understands IPv4, UDP, TCP, ICMP, and ARG
	full = hashlib.md5()
	partial = hashlib.md5()

	if pkt.haslayer(scapy.layers.inet.IP):
		# IPv4, skip ID, fragment info, checksum, and TTL
		ip = pkt.getlayer(scapy.layers.inet.IP)
		full.update(str(ip)[:4])
		full.update(str(ip)[9])
		full.update(str(ip)[12:ip.ihl*4])

		payload = None

		# TCP
		if pkt.haslayer(scapy.layers.inet.TCP):
			tcp = pkt.getlayer(scapy.layers.inet.TCP)
			size_to_check = 16
			full.update(str(tcp)[:size_to_check])
			full.update(str(tcp)[size_to_check + 2:tcp.dataofs*4])
			
			payload = tcp.payload

		# UDP
		elif pkt.haslayer(scapy.layers.inet.UDP):
			udp = pkt.getlayer(scapy.layers.inet.UDP)
			size_to_check = 6
			full.update(str(udp)[:size_to_check])

			payload = udp.payload

		# ICMP
		elif pkt.haslayer(scapy.layers.inet.ICMP):
			icmp = pkt.getlayer(scapy.layers.inet.ICMP)
			size_to_check = 2
			full.update(str(icmp)[:size_to_check])

			payload = icmp.payload

		# ARG
		elif pkt.haslayer(ARGPacket):
			arg = pkt.getlayer(ARGPacket)
			full.update(str(arg)[:136])

			payload = arg.payload

		# And all the stuff under transport
		if payload is not None:
			full.update(str(payload))
			partial.update(str(payload))
			
	else:
		# Just cover everything except the Ethernet layer
		full.update(str(pkt.payload))
		partial = full

	return (full.hexdigest(), partial.hexdigest())	

########################################
# Teach scapy how to parse ARG packets
class ARGPacket(scapy.packet.Packet):
	name = "ARGPacket "
	fields_desc = [	scapy.fields.ByteField("version", 1),
					scapy.fields.ByteField("type", 0),
					scapy.fields.ShortField("len", 0),
					scapy.fields.IntField("seq", 0),
					scapy.fields.XBitField("sig", None, 128*8) ]
scapy.all.bind_layers(scapy.layers.inet.IP, ARGPacket, proto=253)

#########################################
# Main!
def main(argv):
	# Parse command line
	parser = argparse.ArgumentParser(description='Process an ARG test network run')
	parser.add_argument('-l', '--logdir', default='.', help='Directory with pcap and log files from a test')
	parser.add_argument('-db', '--database', default=':memory:',
		help='SQLite database to save packet-tracing data to. If it already exists, \
			we assume it contains trace data. If not given, will be done in memory.')
	parser.add_argument('--empty-database', action='store_true', help='Empties the database if it already exists')
	parser.add_argument('-t', '--skip-trace', action='store_true', help='Do not ensure tracing is complete')
	parser.add_argument('--start-offset', type=int, default=0, help='How many seconds to ignore at the beginning of a run')
	parser.add_argument('--end-offset', type=int, default=0, help='How many seconds to ignore at the end of a run')
	parser.add_argument('--show-cycles', action='store_true', help='If packet trace cycles around found, display the actual packets involved')
	args = parser.parse_args(argv[1:])

	# Ensure database is empty
	# If it is and/or if --empty-database was given, create the schema
	already_exists = os.path.exists(args.database)
	if args.empty_database and already_exists:
		os.unlink(args.database)
		already_exists = False

	# Open database and create schema if it doesn't exist already
	db = sqlite3.connect(args.database)
	if not already_exists:
		try:
			create_schema(db)
			do_record = True
		except sqlite3.OperationalError as e:
			print("Unable to create database: ", e)
			return 1
	else:
		# This database already existed before, check the data to ensure it's at least somewhat filled
		if check_schema(db):
			print('Database already exists, skipping data recording.')
			print('To override this and force a record and trace, give --empty-database on the command line\n')
			do_record = False
		else:
			print('Database already existed, but was unreadable. Re-recording data\n')
			create_schema(db)
			do_record = True

	# Ensure all the systems and settings are in place before we begin
	if do_record:
		read_all_settings(db, args.logdir)
		add_all_systems(db, args.logdir)
		if not check_systems(db):
			print('Problems detected with setup. Correct and re-run the test')
			return 1

	# Trace packets
	if do_record:
		# What did each host attempt to do?
		record_traffic_pcap(db, args.logdir)
		record_traffic_logs(db, args.logdir)

	if not args.skip_trace:
		# Follow each packet through the network and figure out where each packet
		# was meant to go (many were already resolved above, but NAT traffic needs
		# additional assistance)
		trace_packets(db)
		# Check for problems

		cycles = check_for_trace_cycles(db)
		if cycles:
			print('WARNING: Cycles found in trace data. Results may be incorrect')
			if args.show_cycles:
				for id in cycles:
					show_trace(db, id)
			else:
				print('To display the cycles, specify --show-cycles on the command line')

		complete_packet_intentions(db)
		locate_trace_terminations(db)
	elif do_record:
		print('--skip-trace was specified but new data was recorded. Unable to provide stats')
		return 1

	# Collect stats
	print('\n----------------------')
	show_settings(db)
	print()
	print_stats(db, args.start_offset, args.end_offset)

	# All done
	db.commit()
	db.close()

	return 0

if __name__ == '__main__':
	sys.exit(main(sys.argv))

