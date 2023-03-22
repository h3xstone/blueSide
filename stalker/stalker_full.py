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
import face_recognition

# GLOBAL setting
VIDEO_FACE_VALID = 10				# after how many faces found in video is considered found
VIDEO_FACE_MATCH_VALID = 10			# after how many faces match found in video is considered found

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
	'imageTarget': [],
	'videoFaces': [],
	'videoTarget': []
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
	global target_img
	global flag_ci
	global flag_cv

	parser = argparse.ArgumentParser(description="### STALKER FULL VERSION 1.0 ###\n\tby Matt Glow\n\nstalker is a tool designed to help the investigator find all the files related to a person (victim) in the device.\nGiven a victim-name it can search if the victim-name appears in the filename or in its content.\nThis full version can find all photos and videos where faces of people appear and given a victim's photo,\nit can make a comparison to find all photos and videos where the victim appears.", formatter_class=argparse.RawTextHelpFormatter)
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
	parser.add_argument('-i', metavar='imgSample', help='image to search for a match using face recognition and comparison')
	parser.add_argument('-ci', action='store_true', default=False, help='compare in image. Search in images if given <imgSample> is present')
	parser.add_argument('-cv', action='store_true', default=False, help='compare in video. Search in videos if given <imgSample> is present.\nThis will be slow due to checking in each frame')
	parser.add_argument('-a', action='store_true', default=False, help='find all, use this option to search with all previous flags\nwithout having to manually type each option (a = fn + fc + fv + fipp + fvpp + ci + cv)')
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
	target_img = args.i
	flag_ci = args.ci
	flag_cv = args.cv
	
	if (flag_fn or flag_fc or flag_fv or flag_all) and not target_search:
		print(f"{TC.WARN}Error: option '-s <targetName>' missed.{TC.END}")
		sys.exit(0)
	if flag_fv and (not flag_fn and not flag_fc):
		print(f"{TC.WARN}Error: option '-fv' must be used with '-fn' or '-fc' or both.{TC.END}")
		sys.exit(0)
	if flag_all and (flag_fn or flag_fc or flag_fv or flag_fipp or flag_fvpp or flag_ci or flag_cv):
		print(f"{TC.WARN}Error: option '-a' must be used alone in place of the various '-f.., -c..' flags.{TC.END}")
		sys.exit(0)
	if not flag_fn and not flag_fc and not flag_fv and not flag_all and not flag_fipp and not flag_fvpp and not flag_ci and not flag_cv:
		print(f"{TC.WARN}Error: no options given.{TC.END}")
		sys.exit(0)
	if target_search and not (flag_fn or flag_fc or flag_all):
		print(f"{TC.WARN}Error: to search '-s <targetName>' you must provide a option (-fn/-fc/-fv/-a). See help.{TC.END}")
		sys.exit(0)
	if (flag_ci or flag_cv or flag_all) and not target_img:
		print(f"{TC.WARN}Error: option '-i <imgSample>' missed.{TC.END}")
		sys.exit(0)
	if target_img and not (flag_ci or flag_cv or flag_all):
		print(f"{TC.WARN}Error: to search '-i <imgSample>' you must provide a option (-ci/-cv/-a). See help.{TC.END}")
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
		flag_ci = True
		flag_cv = True

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

	# check filetype: text or binary
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
def scanFace(fp,tgt_enc):
	ext = fp.split('.')[-1].lower()
	sheet = cv2.CascadeClassifier(HAAR_FP)
	ppl_found = [False]
	face_found = [False]

	# check img 
	if (flag_fipp or flag_ci) and ext in ['bmp','jpg','jpeg','jpe','jp2','png','pbm','pgm','ppm','sr','tiff','tif']:
		try:
			img = cv2.imread(fp)
		except:
			print(f"\r[{TC.ERR}!{TC.END}] Error: cannot open image: {fp}\t..Skipped..")
			return ppl_found, face_found

		img_gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
		# case face recon
		if flag_ci:
			img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)

		faces = sheet.detectMultiScale(img_gray, 1.2, 10)

		if len(faces) != 0:
			ppl_found = [True, 'imageFaces']
			# case face recon
			if flag_ci:
				# convert box from cv2 (x,y,w,h) to face_recon (top,right,bottom,left)
				face_boxes = [(y,x+w,y+h,x) for (x,y,w,h) in faces]
				boxes_enc = face_recognition.face_encodings(img_rgb, face_boxes)
				for box in boxes_enc:
					res = face_recognition.compare_faces([tgt_enc],box)
					if res[0]:
						face_found = [True, 'imageTarget']
						# stop at first match to speed up
						break
		return ppl_found, face_found

	# check video
	elif (flag_fvpp or flag_cv) and ext in ['avi','mpeg','mp4','3gp']:
		vid = cv2.VideoCapture(fp)
		if vid.isOpened() == False:
			print(f"\r[{TC.ERR}!{TC.END}] Error: cannot open video: {fp}\t..Skipped..")
			return ppl_found, face_found

		faces_count = 0
		faces_match = 0
		while vid.isOpened():
			ret, frame = vid.read()
			if not ret:
				break
			# resize frame to 1/4 to speed up process
			small_frame = cv2.resize(frame, (0,0), fx=0.25, fy=0.25)
			smfr_gray = cv2.cvtColor(small_frame, cv2.COLOR_BGR2GRAY)
			# case face recon
			if flag_cv:
				smfr_rgb = cv2.cvtColor(small_frame, cv2.COLOR_BGR2RGB)

			# since 3gp most of the time has low resolution and due to frame resize
			# increase detection at cost of having more false positive
			if ext == '3gp':
				faces = sheet.detectMultiScale(smfr_gray, 1.1, 5, minSize=(15,15))
			else:
				faces = sheet.detectMultiScale(smfr_gray, 1.1, 5, minSize=(30,30))

			if len(faces) > 0:
				# counter for flag_fvpp
				faces_count += 1
				# case face recon
				if flag_cv:
					face_boxes = [(y,x+w,y+h,x) for (x,y,w,h) in faces]
					boxes_enc = face_recognition.face_encodings(smfr_rgb, face_boxes)
					for box in boxes_enc:
						res = face_recognition.compare_faces([tgt_enc],box)
						if res[0]:
							faces_match += 1
							# stop at first match on each frame to speed up
							break
			
			if flag_fvpp and flag_cv:
				if faces_count >= VIDEO_FACE_VALID:
					ppl_found = [True, 'videoFaces']
					if faces_match >= VIDEO_FACE_MATCH_VALID:
						face_found = [True, 'videoTarget']
						break
			else:
				if flag_fvpp:
					if faces_count >= VIDEO_FACE_VALID:
						ppl_found = [True, 'videoFaces']
						break
				elif flag_cv:
					if faces_match >= VIDEO_FACE_MATCH_VALID:
						face_found = [True, 'videoTarget']
						break

		vid.release()
		return ppl_found, face_found
	else:	
		return ppl_found, face_found

# extract face from sample
def getSampleFace(aface):
	sheet = cv2.CascadeClassifier(HAAR_FP)
	try:
		img = cv2.imread(aface)
	except Exception as err:
		print(f"{TC.ERR}[!] Critical Error: cannot read given image: '{aface}'\nInfo: {err}{TC.END}")
		sys.exit(0)
	img_gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
	img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
	# detect image
	faces = sheet.detectMultiScale(img_gray, 1.2, 10)
	if len(faces) == 0:
		print(f"{TC.ERR}[!] Critical Error: cannot find any face in the given image: '{aface}'{TC.END}")
		sys.exit(0)
	elif len(faces) > 1:
		print(f"{TC.ERR}[!] Critical Error: found many faces in the given image: '{aface}'\n\tPlease use an image with only 1 face inside.{TC.END}")
		sys.exit(0)
	# convert box from cv2 (x,y,w,h) to face_recon (top,right,bottom,left)
	face_box = [(y,x+w,y+h,x) for (x,y,w,h) in faces]
	face_enc = face_recognition.face_encodings(img_rgb, face_box)[0]
	return face_enc


# scan path searching for a match
def main():
	tgt_face_enc = []
	print(f"\r[*] Process folder:\t{TC.SUCC}{target_path}{TC.END}")
	if target_search:
		print(f"\r[*] Search for term:\t{TC.SUCC}{target_search}{TC.END}")
		src_txt = target_search.lower()
	# if using face recon prepare reference face
	if flag_ci or flag_cv:
		print(f"\r[*] Search for face:\t{TC.SUCC}{target_img}{TC.END}")
		tgt_face_enc = getSampleFace(target_img)

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
			# check for people in img and/or do face recon
			if flag_fipp or flag_fvpp or flag_ci or flag_cv:
				if len(tgt_face_enc) != 0 and (flag_ci or flag_cv):
					res_ppl, res_comp = scanFace(fullpath, tgt_face_enc)
				else:
					res_ppl, res_comp = scanFace(fullpath, None)

				if flag_fipp or flag_fvpp:
					if res_ppl[0]:
						print(f"\r[{TC.SUCC}+{TC.END}] found people in {res_ppl[1][:5]}: {fullpath}")
						if flag_of:
							OUT_RES[res_ppl[1]].append(fullpath)
				if flag_ci or flag_cv:
					if res_comp[0]:
						print(f"\r[{TC.SUCC}+{TC.END}] found target-face in {res_comp[1][:5]}: {fullpath}")
						if flag_of:
							OUT_RES[res_comp[1]].append(fullpath)



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