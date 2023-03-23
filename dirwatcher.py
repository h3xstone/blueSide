#!/usr/bin/env python3

"""
PURPOSE:	monitor selected folders every X seconds 
		 	to keep track every changes made
"""  

import sys
import os
from time import sleep
import re

class tc:
	SUCC = '\033[92m'
	ERR = '\033[91m'
	WARN = '\033[93m'
	END = '\033[0m'

try:
	import hashlib
except ImportError:
	print(f"{tc.WARN}You have to install the following module:{tc.ERR} hashlib{tc.END}")
try:
	from deepdiff import DeepDiff
except ImportError:
	print(f"{tc.WARN}You have to install the following module:{tc.ERR} deepdiff{tc.END}")

if len(sys.argv) == 1:
	print(f"Usage: {sys.argv[0]} [-t n] <dir1> <dir2> <dir...>")
	print("Options:")
	print(f"   -t num\t-- optional, watch every N seconds (default: 1)")
	print(f"   <dir..>\t-- required, list of folders to watch\n")
	exit(0)

lst_dir = []
time_check = 1

n = 1
while n <= len(sys.argv[1:]):
	if sys.argv[n].startswith('-t'):
		if len(''.join(sys.argv[n].split('-t'))) > 0:
			time_check = int(''.join(sys.argv[n].split('-t')))
		else:
			time_check = int(sys.argv[n+1])
			n += 1
	else:
		if os.path.exists(sys.argv[n]):
			lst_dir.append(sys.argv[n])
		else:
			print(f"{tc.WARN}ERROR: unable to find folder {tc.ERR}{sys.argv[n]}{tc.END}")
			exit(0)
	n += 1

if len(lst_dir) == 0:
	print(f"{tc.ERR}ERROR: at least 1 directory must be selected.{tc.END}")
	exit(0)

# file hashing
def hashFd(fd):
	md5 = hashlib.md5()
	with open(fd,"rb") as f:
		buff = f.read(8192)
		while buff:
			md5.update(buff)
			buff = f.read(8192)
	return md5.hexdigest()

# monitor folder
def monitor(lst):
	lst_files = {}
	for mon in lst:
		for root,sub,fs in os.walk(mon):
			lst_files[root] = []
			lst_files[root] += sub
			for f in fs:
				fp = root + "/" + f
				lst_files[root].append({f:hashFd(fp)})
	return lst_files

# parse diff result for new and delete
def parseDataND(tup):
	path,fn = tup
	path = re.search(r"root\[(.*)\]\[", path)[1]
	path = path.strip("'")
	fn = next(iter(fn.keys()))
	return path,fn

# parse diff result for edit
def parseDataE(elem):
	path,fn = re.search(r"root\[(.*)\]\[.*\]\[(.*)\]",elem).groups()
	path = path.strip("'")
	fn = fn.strip("'")
	return path,fn

# parse diff res for dir
def parseDir(elem):
	path = re.search(r"root\[(.*)\]", elem)[1]
	path = path.strip("'")
	return path	

def ps(p):
	while len(p) <= 25:
		p += " "
	return p

# get init files
init_files = monitor(lst_dir)

# watch changes
try:
	print(f"{tc.SUCC}+ Running...{tc.END}\n")
	print("OPERATION\tFOLDER\t\t\t\t FILE")
	while True:
		new_files = monitor(lst_dir)
		# check entire dict
		if init_files == new_files:
			pass
		else:
			# check differences
			diff = DeepDiff(init_files,new_files,ignore_order=True)
			
			# iterate throught changes
			for k in diff.keys():
				if k == 'iterable_item_added':
					for el in diff[k].items():
						path,fn = parseDataND(el)

						print(f"{tc.SUCC}[+] NEW{tc.END} \t{ps(path)}\t {fn}")
				elif k == 'iterable_item_removed':
					# case item del
					for el in diff[k].items():
						path,fn = parseDataND(el)
						print(f"{tc.ERR}[-] DELETE{tc.END} \t{ps(path)}\t {fn}")
				elif k == 'values_changed':
					# case item edit
					for el in diff[k].keys():
						path,fn = parseDataE(el)
						print(f"{tc.WARN}[*] EDIT{tc.END} \t{ps(path)}\t {fn}")
				elif k == 'dictionary_item_added':
					# case new folder
					for el in diff[k]:
						path = parseDir(el)
						print(f"{tc.SUCC}[+] NEW{tc.END} \t{ps(path)}\t (folder)")
					break
				elif k == 'dictionary_item_removed':
					# case del folder
					for el in diff[k]:
						path = parseDir(el)
						print(f"{tc.ERR}[-] DELETE{tc.END} \t{ps(path)}\t (folder)")
					break
				else:
					# unknow
					print(f"{tc.ERR}[!]{tc.END} Detected UNKNOWN operation =>\t{tc.WARN}{k}{tc.END}")

		init_files = monitor(lst_dir)
		sleep(time_check)
except KeyboardInterrupt:
	print("\nExit")
	exit(0)