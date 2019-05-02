#!/usr/bin/env python3

#
# PaReD.py
# --------
# A simple Python script that tries to determine one or more FQDNs of a given IP
# address using passive reverse DNS lookups.
# At the moment it gets data from SecurityTrails (https://securitytrails.com/).
#
# Coded by: Riccardo Mollo (riccardomollo84@gmail.com)
#

import argparse
import getopt
import ipaddress
import re
import requests
import signal
import sys
import urllib3
from termcolor import colored

requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL'
requests.packages.urllib3.contrib.pyopenssl.extract_from_urllib3()
urllib3.disable_warnings()

def signal_handler(s, frame):
    if s == 2: # SIGINT
        print('You pressed Ctrl+C!')
        print('Goodbye!')
        sys.exit()

def logo():
    print(colored(' _   _   _ ', 'cyan'))
    print(colored('|_)_|_)_| \\', 'cyan'))
    print(colored('| (_| (/|_/', 'cyan'))
    print(colored('PaReD - Passive Reverse DNS lookup tool', 'cyan'))
    print(colored('Coded by: Riccardo Mollo', 'cyan'))
    print()

def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', help = 'The IP address', required = True)
    args = parser.parse_args()
    ip = args.ip
    ua = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'

    logo()

    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        print(colored('ERROR!', 'red', attrs=['reverse', 'bold']) + ' IP address is not valid.')
        sys.exit(1)

    print('[+] IP: ' + colored(ip, 'white', attrs=['bold']))

    url = 'https://securitytrails.com/list/ip/' + ip

    r = requests.get(url, headers={'User-Agent': ua}, verify=False)
    fqdns = re.findall('dns\"\>(.*?)\<\/a\>', r.text)
    count = len(fqdns)

    if count > 0:
        n = colored(str(count), 'green')
        print('[+] Found ' + n + ' domains:')

        for fqdn in fqdns:
            print('    ' + colored(fqdn, 'green'))
    else:
        print('[+] No domains found, sorry.')

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    main(sys.argv[1:])

#### TODO:
#### - output file

