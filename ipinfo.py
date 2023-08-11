import requests
import json
import argparse
import os.path
import ipaddress

# GLOBAL CONST
APIKEY = "YOUR-PERSONAL-ABUSEIPDB-API-TOKEN-HERE"
SCORE_TABLE = {
				1: 'DNS Compromise',
				2: 'DNS Poisoning',
				3: 'Fraud Orders',
				4: 'DDoS Attack',
				5: 'FTP Brute-Force',
				6: 'Ping of Death',
				7: 'Phishing',
				8: 'Fraud VoIP',
				9: 'Open Proxy',
				10: 'Web Spam',
				11: 'Email Spam',
				12: 'Blog Spam',
				13: 'VPN IP',
				14: 'Port Scan',
				15: 'Hacking',
				16: 'SQL Injection',
				17: 'Spoofing',
				18: 'Brute-Force',
				19: 'Bad Web Bot',
				20: 'Exploited Host',
				21: 'Web App Attack',
				22: 'SSH abuse',
				23: 'IoT Targeted'
			}

# args
pn = os.path.basename(__file__)
desc = f"### ABOUT: given an IP, script will gather Category and Country from abuseipdb ###\n\n\
Example:\n\n\
- {pn}                         interactive mode: you will be asked to enter data\n\
- {pn} 11.22.33.44             get info for single ip\n\
- {pn} -f ip_list.txt          get info for each ip in file (ip must be line-by-line)\n\
"

parser = argparse.ArgumentParser(description=desc, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('ip', nargs='?', help='ip target')
parser.add_argument('-f', metavar='ip_list', help='file with list of ips')
args = parser.parse_args()

ip = args.ip
fl = args.f

# validate ip
def checkIP(ip):
	try:
		res = ipaddress.ip_address(ip)
		return True
	except ValueError:
		return False

# check ip on abuse
def gatherInfo(ip):
	URL = "https://api.abuseipdb.com/api/v2/check"
	q = {
			'ipAddress': ip,
			'verbose': True,
			'maxAgeInDays': '90'
		}
	hdrs = {
			'Accept': 'application/json',
			'Key': APIKEY
		}

	req = requests.get(URL, params=q, headers=hdrs)
	resp = req.json()

	# extract country
	country = resp['data']['countryName']

	# extract attack type
	attack_list = []
	report_list = resp['data']['reports']
	cat_list = [atk['categories'] for atk in report_list]
	for arrc in cat_list:
		for sc in arrc:
			if sc and sc not in attack_list:
				attack_list.append(sc)

	# show result format table
	# -----------------------------------
	# |   IP   |  Category  |  Country  |
	# -----------------------------------

	print(ip, end='\t')
	for x in attack_list:
		if attack_list[-1] == x:
			print(SCORE_TABLE[x], end='\t')
		else:
			print(SCORE_TABLE[x], end=', ')
	print(country)

# main
if ip and fl:
	print("ERROR: provide only one parameter at time (single IP or IP list or None)")
	exit(0)

if not fl:
	if ip:
		if checkIP(ip):
			print("[START]\n\n")
			gatherInfo(ip)
		else:
			print(f"ERROR: '{ip}' is not a valid ip")
			exit(0)
	else:
		iplist = []
		print("Insert ip, list of ips or file of ips-list ( when done press [ENTER]x2 ) :")
		while True:
			try:
				ans = input()
				if not ans:
					break
			except EOFError:
				break
			except KeyboardInterrupt:
				exit(0)
			iplist.append(ans)

		iplist = list(filter(None, iplist))
		print("[START]\n\n")

		if not iplist:
			print("ERROR: no ips to process")
			exit(0)

		if len(iplist) == 1:
			elem = iplist[0]
			# check if ip or fd
			if checkIP(elem):
				gatherInfo(elem)
			elif os.path.isfile(elem):
				with open(elem,'r') as fd:
					iplist = fd.readlines()
				iplist = [x.strip() for x in iplist if x.strip()]
				for ip in iplist:
					if checkIP(ip):
						gatherInfo(ip)
					else:
						print(f"ERROR: '{ip}' is not a valid ip")
			else:
				print("ERROR: file or ips are not a valid.")
				exit(0)
		else:
			for ip in iplist:
				if ip != '':
					if checkIP(ip):
						gatherInfo(ip)
					else:
						print(f"ERROR: '{ip}' is not a valid ip")
else:
	# parse file
	try:
		iplist = []
		with open(fl,'r') as fd:
			iplist = fd.readlines()
			iplist = [x.strip() for x in iplist if x.strip()]
			print("[START]\n\n")
			for ip in iplist:
				if checkIP(ip):
					gatherInfo(ip)
				else:
					print(f"ERROR: '{ip}' is not a valid ip")
	except:
		print("ERROR: cannot open file.")
		exit(0)
