#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import hashlib
from datetime import datetime as dt
import argparse

class TC:
	SUCC = '\033[92m'
	ERR = '\033[91m'
	WARN = '\033[93m'
	END = '\033[0m'

def getMD5(fd):
	hash_md5 = hashlib.md5()
	with open(fd, 'rb') as f:
		for chunk in iter(lambda: f.read(4096), b''):
			hash_md5.update(chunk)
	return hash_md5.hexdigest()


def scrapeDir(path):
	lst_files = {}
	for root, sub, fl in os.walk(path):
		for f in fl:
			fullpath = os.path.join(root,f)
			lst_files[fullpath] = getMD5(fullpath)
	return lst_files


def main():
	desc = '''
**********************************************************
**                 WordPress IOC checker                **
**  \x1B[3mQuickly check if your WP site has been compromised\x1B[0m  **
**********************************************************
'''
	ep = '''
Example:
   wpIOChecker.py -p /var/www/myWPsite -g                          // generate a report of current state
   wpIOChecker.py -p /var/www/myWPsite -r report_old.json -diff    // check differences between previous and current state
   wpIOChecker.py -r report_day1.json report_day2.json -diff       // check differences between old and recent state
'''
	parser = argparse.ArgumentParser(description=desc, epilog=ep, formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument('-p', metavar='targetPath', help='path of WordPress Installation')
	parser.add_argument('-g', action='store_true', default=False, help='generate a file with the list of all files associated with their hash')
	parser.add_argument('-diff', action='store_true', default=False, help='compare two report, or old report with current WP state')
	parser.add_argument('-r', metavar='report.json', nargs='+', help='report to compare. Please use the following order: old, new')

	args = parser.parse_args()

	wp_path = args.p
	flag_genRep = args.g
	flag_diff = args.diff
	lst_report = args.r

	if not wp_path and not flag_genRep and not flag_diff and not lst_report:
		print(f"{TC.WARN}ERROR: no options given{TC.END}")
		exit(0)
	if wp_path and not flag_genRep and not flag_diff and not lst_report:
		print(f"{TC.WARN}ERROR: no options given{TC.END}")
		exit(0)
	if flag_genRep and not wp_path:
		print(f"{TC.WARN}ERROR: to generate a report you need to provide a Wordpress Installation folder. Option '-p <targetPath> missed{TC.END}")
		exit(0)
	if flag_genRep and wp_path and (flag_diff or lst_report):
		print(f"{TC.WARN}ERROR: option '-g' must be used only with option '-p target'{TC.END}")
		exit(0)
	if flag_diff:
		if wp_path and not lst_report:
			print(f"{TC.WARN}ERROR: report to compare missed. Select one with the option '-r <report.json>'{TC.END}")
			exit(0)
		if wp_path and len(lst_report) > 1:
			print(f"{TC.WARN}ERROR: comparison with WP folder require only one report, {len(lst_report)} given{TC.END}")
			exit(0)
		if len(lst_report) != 2 and not wp_path:
			print(f"{TC.WARN}ERROR: to compare report you need to provide only 2 report in the following format: '-r report1.json report2.json' , {len(lst_report)} given{TC.END}")
			exit(0)

	if lst_report and len(lst_report) !=0 and not flag_diff:
		print(f"{TC.WARN}ERROR: option '-diff' missed{TC.END}")
		exit(0)

	if wp_path and not os.path.isdir(wp_path):
		print(f"{TC.WARN}ERROR: option -p '{wp_path}' must be a folder{TC.END}")
		exit(0)
	if lst_report:
		for r in lst_report:
			if not os.path.isfile(r):
				print(f"{TC.WARN}ERROR: {r} is not a file{TC.END}")
				exit(0)
			elif r.split('.')[-1].lower() != 'json':
				print(f"{TC.WARN}ERROR: {r} is not a json report{TC.END}")
				exit(0)

	print(f"{TC.SUCC}[STARTED]{TC.END}")
	# generate report
	if flag_genRep:
		report_data = scrapeDir(wp_path)
		dt_now = dt.utcnow()
		dt_now = dt_now.strftime('%Y-%m-%d__%H-%M')
		fout = 'wpIOC_report__' + dt_now + '.json'
		try:
			with open(fout, 'w') as fp:
				json.dump(report_data, fp)
				print(f"{TC.SUCC}Report generated and saved @ {os.path.join(os.path.abspath('.'),fout)}{TC.END}")
				exit(0)
		except Exception as err:
			print(f"{TC.ERR}ERROR: cannot save result @ {os.path.join(os.path.abspath('.'),fout)}\nINFO:\t{err}{TC.END}")
			exit(0)

	# diff
	if flag_diff:
		# diff wp - report
		if wp_path:
			new_data = scrapeDir(wp_path)
			try:
				with open(lst_report[0], 'r') as fp:
					old_data = json.load(fp)
			except Exception as err:
				print(f"{TC.ERR}ERROR: cannot read {lst_report[0]}\nINFO:\t{err}{TC.END}")
				exit(0)
		elif len(lst_report) == 2:
			# diff report - report
			try:
				with open(lst_report[0], 'r') as fp1, open(lst_report[1], 'r') as fp2:
					old_data = json.load(fp1)
					new_data = json.load(fp2)
			except Exception as err:
				print(f"{TC.ERR}ERROR: cannot read report\nINFO:\t{err}{TC.END}")
				exit(0)

		# compare files
		# sort by key
		old_data = dict(sorted(old_data.items()))
		new_data = dict(sorted(new_data.items()))
		diff_data = set(old_data.items()) ^ set(new_data.items())
		count = 0
		if diff_data:
			for dd in dict(diff_data):
				if dd in old_data.keys() and dd not in new_data.keys():
					count += 1
					print(f"[{TC.ERR}!{TC.END}] Deleted {dd}")
				elif dd not in old_data.keys() and dd in new_data.keys():
					count += 1
					print(f"[{TC.ERR}!{TC.END}] New {dd}")
				elif dd in old_data.keys() and dd in new_data.keys():
					count += 1
					print(f"[{TC.ERR}!{TC.END}] Changed {dd}")
			print(f"\n{TC.ERR}[!!] Found Total of {count} different files!{TC.END}\n")
		else:
			print(f"{TC.SUCC}Good News! Your site has NOT been touched!{TC.END}\n\t\t\t\t\x1B[3m...at least for now... ;)\x1B[0m\n")

if __name__ == '__main__':
	main()