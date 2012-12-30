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

def get_stats(result_dir, begin_time_buffer=None, end_time_buffer=None, remove_bad=False):
	print('Getting stats...', end='')

	all_stats = list()
	for db_path in glob(os.path.join(result_dir, '*', '*.db')):
		# Open database
		db = None
		try:
			db = sqlite3.connect(db_path)
			if check_complete(db):
				sys.stdout.flush()
			else:
				raise Exception('contents are invalid'.format(db_path))
		
			# Get settings and stats for this run, then combine
			settings = get_all_settings(db)
			settings['results.database'] = db_path
			stats = generate_stats(db, begin_time_buffer, end_time_buffer)
			stats = (dict(stats[0].items() + settings.items()), stats[1])
		except Exception as e:
			print('\nFound database at {}, but unable to use ({})'.format(db_path, str(e)))
			print('Continuing to get stats...', end='')

			if remove_bad:
				print('Removing bad database')
				os.unlink(db_path)

			continue

		# We only care about the number of times each loss method was used
		loss_counts = {k.replace(' ', '.').lower(): len(packets) for k, packets in stats[1].iteritems()}

		all_stats.append((stats[0], loss_counts))

		db.close()

		print('.', end='')
		sys.stdout.flush()

	print('done')
	return all_stats

def get_headers(all_stats):
	# Grab the headers for each database. Most are the same, but the loss ones may not be
	# represented fully in all of the results
	print('Getting unique headers...', end='')

	stat_headers = set()
	loss_headers = set()
	for s in all_stats:
		stats, losses = s
		stat_headers |= set(stats.keys())
		loss_headers |= set(losses.keys())

		print('.', end='')
		sys.stdout.flush()

	print('done')
	return (list(stat_headers), list(loss_headers))

def create_csv(csv_path, headers, all_stats):
	# Creates and outputs a CSV file containing the stats
	print('Creating CSV at {}...'.format(csv_path), end='')

	with open(csv_path, 'w') as csv:
		# Header (settings, normal, and loss causes)
		for header in headers:
			for h in sorted(header):
				if h.endswith('.examples'):
					continue

				csv.write('"{}",'.format(h.replace(' ', '.').lower()))

		csv.write('\n')

		# Data
		for stats in all_stats:
			for i in range(len(headers)):
				for h in sorted(headers[i]):
					if h.endswith('.examples'):
						continue

					try:
						csv.write('"{}",'.format(stats[i][h]))
					except KeyError:
						csv.write(',')

			csv.write('\n')

			print('.', end='')
			sys.stdout.flush()

	print('done')

def main(argv):
	parser = argparse.ArgumentParser(description='Process an ARG test network run')
	parser.add_argument('--offset', type=int, default=0, help='How many seconds to ignore at beginning AND end of run. Overriden by --start-offset and --end-offset')
	parser.add_argument('--start-offset', type=int, default=None, help='How many seconds to ignore at the beginning of a run')
	parser.add_argument('--end-offset', type=int, default=None, help='How many seconds to ignore at the end of a run')
	parser.add_argument('-r', '--results-dir', default='.', help='Directory with results. Only already-filled DB files will be processed.')
	parser.add_argument('-o', '--csv', required=True, help='CSV file to save consolidated results to')
	parser.add_argument('--remove-bad', action='store_true', help='If given, removes invalid run.db files')
	args = parser.parse_args(argv[1:])

	# Offsets
	if args.start_offset is None:
		args.start_offset = args.offset
	if args.end_offset is None:
		args.end_offset = args.offset

	all_stats = get_stats(args.results_dir, args.start_offset, args.end_offset, remove_bad=args.remove_bad)
	headers = get_headers(all_stats)
	create_csv(args.csv, headers, all_stats)

if __name__ == '__main__':
	sys.exit(main(sys.argv))

