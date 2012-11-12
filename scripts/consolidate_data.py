#!/usr/bin/env python
from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division

import sys
import time
import os
import sys
import sqlite3
import argparse
import re
from glob import glob

from process_run import *

def get_databases(result_dir):
	# Grab and open all the databases 
	print('Opening databases...', end='')

	dbs = list()
	for db_path in glob(os.path.join(result_dir, '*', '*.db')):
		db = sqlite3.connect(db_path)
		if check_schema(db):
			print('.', end='')
			sys.stdout.flush()
			dbs.append(db)
		else:
			print('\n\tFound database at {}, but contents are invalid'.format(db_path))
			print('Continuing to open', end='')

	print('done')
	return dbs

def get_stats(dbs, begin_time_buffer=None, end_time_buffer=None):
	print('Getting stats...', end='')

	all_stats = list()
	for db in dbs:
		all_stats.append(generate_parsable_stats(db, begin_time_buffer, end_time_buffer))
		print('.', end='')
		sys.stdout.flush()

	print('done')
	return all_stats

def get_headers(all_stats):
	# Grab the headers for each database. Most are the same, but the loss ones may not be
	# represented fully in all of the results
	print('Getting unique headers...', end='')

	headers = set()
	for stats in all_stats:
		headers |= set(stats.keys())
		print('.', end='')
		sys.stdout.flush()

	print('done')
	return list(headers)

def create_csv(csv_path, headers, all_stats):
	# Creates and outputs a CSV file containing the stats
	print('Creating CSV at {}...'.format(csv_path), end='')

	with open(csv_path, 'w') as csv:
		# Header
		for h in sorted(headers):
			csv.write('"{}",'.format(h))
		csv.write('\n')

		# Data
		for stats in all_stats:
			print('.', end='')
			for h in sorted(headers):
				try:
					csv.write('{},'.format(stats[h]))
				except KeyError:
					csv.write(',')
			csv.write('\n')

	print('done')

def main(argv):
	parser = argparse.ArgumentParser(description='Process an ARG test network run')
	parser.add_argument('--start-offset', type=int, default=0, help='How many seconds to ignore at the beginning of a run')
	parser.add_argument('--end-offset', type=int, default=0, help='How many seconds to ignore at the end of a run')
	parser.add_argument('-r', '--results-dir', default='.', help='Directory with results. Only already-filled DB files will be processed.')
	parser.add_argument('-o', '--csv', required=True, help='CSV file to save consolidated results to')
	args = parser.parse_args(argv[1:])

	dbs = get_databases(args.results_dir)
	all_stats = get_stats(dbs)
	headers = get_headers(all_stats)
	create_csv(args.csv, headers, all_stats)

if __name__ == '__main__':
	sys.exit(main(sys.argv))

