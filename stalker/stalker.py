#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import mmap
import zipfile
import argparse
import cv2
from time import sleep
from threading import Thread
import json
import re

# GLOBAL setting
VIDEO_FACE_VALID = 10				# after how many faces found in video is considered found

# func needed for pyinstaller
def getPath(p):
	try:
		bp = sys._MEIPASS
	except Exception:
		bp = os.path.abspath('.')
	return os.path.join(bp,p)

HAAR_FP = getPath("haarcascade_frontalface_default.xml")
OUT_RES = {
	'dir': [],
	'filename': [],
	'filecontent': [],
	'imageFaces': [],
	'videoFaces': []
}

# colors
if sys.platform == 'win32':
	import colorama
	colorama.init()
	class TC:
		SUCC = colorama.Fore.GREEN
		ERR = colorama.Fore.RED
		WARN = colorama.Fore.YELLOW
		END = colorama.Style.RESET_ALL
else:
	class TC:
		SUCC = '\033[92m'
		ERR = '\033[91m'
		WARN = '\033[93m'
		END = '\033[0m'

# loading animation
class Loading:
	def __init__(self):
		self.timeout = 0.3
		self.th = Thread(target=self.animate, daemon=True)
		self.done = False

	def start(self):
		self.th.start()

	def animate(self):
		while not self.done:
			for ch in ['|','/','-','\\']:
				print(f"\r{ch}",end="")
				sleep(self.timeout)

	def stop(self):
		self.done = True
		print("\r ")

# parse args
def parseArgs():
	global target_path
	global target_search
	global flag_fn
	global flag_fc
	global flag_fv
	global flag_fipp
	global flag_fvpp
	global out_file
	global flag_of

	parser = argparse.ArgumentParser(description='### STALKER LIGHT VERSION 1.0 ###\n\tby Matt Glow\n\nstalker is a tool designed to help the investigator find all the files related to a person (victim) in the device.\nGiven a victim-name it can search if the victim-name appears in the filename or in its content.\nThis light version can find all photos and videos where faces of people appear.', formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument('-p', metavar='fullpath', required=True, help='path where start searching recursively (required)')
	parser.add_argument('-s', metavar='targetName', type=str, help='name/text to search')
	parser.add_argument('-fn', action='store_true', default=False, help='search for match in filename')
	parser.add_argument('-fc', action='store_true', default=False, help='search for match in file content')
	parser.add_argument('-fv', action='store_true', default=False, help='''used with -fn and/or -fc search by original and variants.
	Example:
	 - Original term:  steven  |  leet
	 - 1st variant:    st3v3n  |  l33t	(vowel substitution)
	 - 2nd variant:    57even  |  1ee7	(consonants substitution)
	 - 3rd variant:    573v3n  |  1337	(both)''')
	parser.add_argument('-fipp', action='store_true', default=False, help='find images containing human faces')
	parser.add_argument('-fvpp', action='store_true', default=False, help='find videos containing human faces. This will be slow due to checking in each frame')
	parser.add_argument('-a', action='store_true', default=False, help='find all, use this option to search with all previous flags\nwithout having to manually type each option (a = fn + fc + fv + fipp + fvpp)')
	parser.add_argument('-o', metavar='outfile.json', help='save result to file in json format\n\n')

	args = parser.parse_args()

	target_path = args.p
	target_search = args.s
	flag_fn = args.fn
	flag_fc = args.fc
	flag_fv = args.fv
	flag_fipp = args.fipp
	flag_fvpp = args.fvpp
	flag_all = args.a
	out_file = args.o
	
	if (flag_fn or flag_fc or flag_fv or flag_all) and not target_search:
		print(f"{TC.WARN}Error: option '-s <targetName>' missed.{TC.END}")
		sys.exit(0)
	if flag_fv and (not flag_fn and not flag_fc):
		print(f"{TC.WARN}Error: option '-fv' must be used with '-fn' or '-fc' or both.{TC.END}")
		sys.exit(0)
	if flag_all and (flag_fn or flag_fc or flag_fv or flag_fipp or flag_fvpp):
		print(f"{TC.WARN}Error: option '-a' must be used alone in place of the various '-f..' flags.{TC.END}")
		sys.exit(0)
	if not flag_fn and not flag_fc and not flag_fv and not flag_all and not flag_fipp and not flag_fvpp:
		print(f"{TC.WARN}Error: no options given.{TC.END}")
		sys.exit(0)
	if target_search and not (flag_fn or flag_fc or flag_all):
		print(f"{TC.WARN}Error: to search '-s <targetName>' you must provide a option (-fn/-fc/-fv/-a). See help.{TC.END}")
		sys.exit(0)

	if not os.path.isdir(target_path):
		print(f"{TC.WARN}Error: path must be a folder!{TC.END}")
		sys.exit(0)

	if out_file:
		flag_of = True
	else:
		flag_of = False

	if flag_all:
		flag_fn = True
		flag_fc = True
		flag_fv = True
		flag_fipp = True
		flag_fvpp = True

# transform to variant
def getVariant(s):
	vow = {'a':4,'e':3,'i':1,'o':0}
	cons = {'s':5,'t':7,'l':1}
	
	# variant vowels
	str_v = [str(vow[c]) if c in vow.keys() else c for c in s]
	str_v = ''.join(str_v)
	# variant consonants
	str_c = [str(cons[c]) if c in cons.keys() else c for c in s]
	str_c = ''.join(str_c)
	# mix both
	str_mix = [str(cons[c]) if c in cons.keys() else c for c in str_v]
	str_mix = ''.join(str_mix)

	return str_v, str_c, str_mix
	
# parse Word Documents
def parseDoc(fp,ext,term):
	doc = zipfile.ZipFile(fp)
	try:
		if ext.startswith('d',0,1):
			# MS Office
			data = doc.read('word/document.xml')
		elif ext.startswith('o',0,1):
			# Libre Office
			data = doc.read('content.xml')
	except:
		# xml not found
		pass

	return term.encode() in data.lower()

# check for txt match in file content
def scanFile(fp,txt):
	file_sig = {
				"25504446":"PDF",
				"504B0304":"ZIP",
				"D0CF11E0":"DOC"
			}

	use_map = True
	CHUNK_SIZE = 2048
	
	# if size > 512MB read by chunck instead of mmap entire file
	fsize = os.path.getsize(fp) / 1_000_000
	if fsize > 512:
		use_map = False

	# check filetype if text or binary
	try:
		with open(fp,'r') as fd:
			data = fd.read(16)
			fd.seek(0)

			# no error => file is text => look inside for txt
			if use_map:
				with mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_READ) as data:
					# data to lower
					data = data.read().decode().lower()
					if data.find(txt) != -1:
						return True
			else:
				while True:
					chunck = fd.read(CHUNK_SIZE)
					if not chunck:
						break
					if txt in chunck.lower():
						return True
	except:
		# error => binary file => identify file
		with open(fp,'rb',0) as fd:
			# check signature
			sig = fd.read(4).hex().upper()
			fd.seek(0)
			
			# case docs readable
			if sig in file_sig.keys():
				# case .pdf
				if file_sig[sig] == 'PDF':
					if use_map:
						with mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_READ) as data:
							# due to different encoding many times pdf raises a codec error
							try:
								pattern = re.compile(txt.encode(),re.IGNORECASE)
								if pattern.search(data) != None:
									return True
							except:
								print(f"\r[{TC.ERR}!{TC.END}] failed read file: {fp}\t..Skipped..")
					else:
						try:
							while True:
								chunck = fd.read(CHUNK_SIZE)
								if not chunck:
									break
								pattern = re.compile(txt.encode(),re.IGNORECASE)
								if pattern.search(chunck) != None:
									return True
						except:
							print(f"\r[{TC.ERR}!{TC.END}] failed read file: {fp}\t..Skipped..")
				# case .doc .dot
				elif file_sig[sig] == 'DOC':
					if use_map:
						with mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_READ) as data:
							# clean data to find text
							data = data.read().replace(b'\xff',b'').replace(b'\x00',b'')
							pattern = re.compile(txt.encode(),re.IGNORECASE)
							if pattern.search(data) != None:
								return True
					else:
						while True:
							chunck = fd.read(CHUNK_SIZE).replace(b'\xff',b'').replace(b'\x00',b'')
							if not chunck:
								break
							pattern = re.compile(txt.encode(),re.IGNORECASE)
							if pattern.search(chunck) != None:
								return True
				# case common docs
				elif file_sig[sig] == 'ZIP':
					# check if docs
					ext = fp.split('.')[-1].lower()
					if ext in ['docm','docx','dotm','dotx','odt','ott']:
						if parseDoc(fp,ext,txt):
							return True
					else:
						print(f"\r[{TC.ERR}-{TC.END}] file format not handled: {fp}\t..Skipped..")
			else:
				# case .csv
				# other files like img,video,etc or unreadable due to codec are skipped
				if fp.split('.')[-1].lower() == 'csv':
					if use_map:
						with mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_READ) as data:
							pattern = re.compile(txt.encode(),re.IGNORECASE)
							if pattern.search(data) != None:
								return True
					else:
						while True:
							chunck = fd.read(CHUNK_SIZE)
							if not chunck:
								break
							pattern = re.compile(txt.encode(),re.IGNORECASE)
							if pattern.search(chunck) != None:
								return True

# search for face in image or video
def scanFace(fp):
	ext = fp.split('.')[-1].lower()
	sheet = cv2.CascadeClassifier(HAAR_FP)
	# check img 
	if flag_fipp and ext in ['bmp','jpg','jpeg','jpe','jp2','png','pbm','pgm','ppm','sr','tiff','tif']:
		try:
			img = cv2.imread(fp)
		except:
			print(f"\r[{TC.ERR}!{TC.END}] Error: cannot open image: {fp}\t..Skipped..")
			return [False]

		img_gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
		faces = sheet.detectMultiScale(img_gray, 1.2, 10)
		if len(faces) != 0:
			return [True, 'imageFaces']
		else:
			return [False]
	# check video
	elif flag_fvpp and ext in ['avi','mpeg','mp4','3gp']:
		vid = cv2.VideoCapture(fp)
		if vid.isOpened() == False:
			print(f"\r[{TC.ERR}!{TC.END}] Error: cannot open video: {fp}\t..Skipped..")
			return [False]
		faces_count = 0
		while vid.isOpened() and faces_count < VIDEO_FACE_VALID:
			ret, frame = vid.read()
			if not ret:
				break
			# resize frame to 1/4 to speed up process
			small_frame = cv2.resize(frame, (0,0), fx=0.25, fy=0.25)
			smfr_gray = cv2.cvtColor(small_frame, cv2.COLOR_BGR2GRAY)
			
			# since 3gp most of the time has low resolution and due to frame resize
			# increase detection at cost of having more false positive
			if ext == '3gp':
				faces = sheet.detectMultiScale(smfr_gray, 1.1, 5, minSize=(15,15))
			else:
				faces = sheet.detectMultiScale(smfr_gray, 1.1, 5, minSize=(30,30))

			if len(faces) > 0:
				faces_count += 1

		vid.release()
		if faces_count >= VIDEO_FACE_VALID:
			return [True, 'videoFaces']
		else:
			return [False]
	else:
		return [False]
	
# scan path searching for a match
def main():
	print(f"\r[*] Process folder:\t{TC.SUCC}{target_path}{TC.END}")
	if target_search:
		print(f"\r[*] Search for term:\t{TC.SUCC}{target_search}{TC.END}")
		src_txt = target_search.lower()

	print("\r ")

	for root,dirs,files in os.walk(target_path):
		# filename -> check also dir name
		if flag_fn:
			# check variant
			if flag_fv:
				src_v,src_c,src_m = getVariant(src_txt)
				for d in dirs:
					if src_txt in d.lower() or src_v in d.lower() or src_c in d.lower() or src_m in d.lower():
						print(f"\r[{TC.SUCC}+{TC.END}] found name-variant folder:",os.path.join(root,d))
						if flag_of:
							OUT_RES['dir'].append(os.path.join(root,d))
			else:
				for d in dirs:
					if src_txt in d.lower():
						print(f"\r[{TC.SUCC}+{TC.END}] found folder:",os.path.join(root,d))
						if flag_of:
							OUT_RES['dir'].append(os.path.join(root,d))
		# check files
		for f in files:
			fullpath = os.path.join(root,f)
			# check filename
			if flag_fn:
				# check variant
				if flag_fv:
					src_v,src_c,src_m = getVariant(src_txt)
					if src_txt in f.lower() or src_v in f.lower() or src_c in f.lower() or src_m in f.lower():
						print(f"\r[{TC.SUCC}+{TC.END}] found name-variant file:",fullpath)
						if flag_of:
							OUT_RES['filename'].append(fullpath)
				else:
					if src_txt in f.lower():
						print(f"\r[{TC.SUCC}+{TC.END}] found file:",fullpath)
						if flag_of:
							OUT_RES['filename'].append(fullpath)
			# check content
			if flag_fc:
				# check variant
				if flag_fv:
					src_v,src_c,src_m = getVariant(src_txt)
					for sample in [src_txt, src_v, src_c, src_m]:
						if scanFile(fullpath,sample):
							print(f"\r[{TC.SUCC}+{TC.END}] found variant '{sample}' content in file:",fullpath)
							if flag_of:
								OUT_RES['filecontent'].append(fullpath)
				else:
					if scanFile(fullpath,src_txt):
						print(f"\r[{TC.SUCC}+{TC.END}] found content in file:",fullpath)
						if flag_of:
							OUT_RES['filecontent'].append(fullpath)
			# check for people in img
			if flag_fipp or flag_fvpp:
				res = scanFace(fullpath)
				if res[0]:
					print(f"\r[{TC.SUCC}+{TC.END}] found people in {res[1][:5]}: {fullpath}")
					if flag_of:
						OUT_RES[res[1]].append(fullpath)


if __name__ == "__main__":
	parseArgs()
	print(f"{TC.SUCC}[START]{TC.END}")
	loader = Loading()
	loader.start()
	try:
		main()
		loader.stop()
		if flag_of:
			try:
				with open(out_file,"w") as fd:
					json.dump(OUT_RES,fd)
					print(f"[{TC.SUCC}+{TC.END}] Results saved to '{TC.SUCC}{os.path.join(os.path.abspath('.'),out_file)}{TC.END}'")
			except Exception as err:
				print(f"{TC.ERR}Error write to '{os.path.join(os.path.abspath('.'),out_file)}'.\nInfo: {err}{TC.END}\n")
		print(f"{TC.SUCC}[END]{TC.END}")
	except KeyboardInterrupt:
		loader.stop()
		# save anyway collected data
		if flag_of:
			try:
				with open(out_file,"w") as fd:
					json.dump(OUT_RES,fd)
					print(f"[{TC.SUCC}+{TC.END}] Results before stop saved to '{TC.SUCC}{os.path.join(os.path.abspath('.'),out_file)}{TC.END}'")
			except Exception as err:
				print(f"{TC.ERR}Error write to '{os.path.join(os.path.abspath('.'),out_file)}'.\nInfo: {err}{TC.END}\n")
		print(f"{TC.WARN}[STOPPED by USER]{TC.END}")
		sys.exit(0)