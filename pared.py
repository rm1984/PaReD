#!/usr/bin/env python3

#
# PaReD.py
# --------
# A simple Python script that tries to determine one or more FQDNs of a given IP
# address using passive reverse DNS lookups.
# At the moment it can retrieve data from HackerTarget's API
# (https://hackertarget.com/) and from Mnemonic by Argus Managed Defence
# (https://passivedns.mnemonic.no/), since SecurityTrails massively changed its
# front-end query page and getting results is now a pain in the @$$.
#
# Coded by: Riccardo Mollo (riccardomollo84@gmail.com)
#

#### TODO:
#### - possibly merge results from all providers

import argparse
import calendar
import getopt
import ipaddress
import json
import random
import requests
import signal
import sys
import time
import urllib3
from dns import reversename, resolver
from ipaddress import IPv4Network
from pathlib import Path
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

def error(message):
    print(colored('ERROR!', 'red', attrs = ['reverse', 'bold']) + ' ' + message)

# HackerTarget
def from_hackertarget(ip, ua):
    url = 'https://api.hackertarget.com/reverseiplookup/?q=' + ip

    r = requests.get(url, headers = {'User-Agent' : ua}, verify = False)

    if r.status_code != 200:
        error('Server responded with HTTP code ' + str(r.status_code) + '.')
        sys.exit(1)

    if 'API count exceeded' in r.text:
        error('API count exceeded.')
        sys.exit(1)

    fqdns = []

    if 'No DNS A records found' not in r.text:
        fqdns = r.text.splitlines()

    return fqdns

# Argus Managed Defence | mnemonic
def from_mnemonic(ip, ua):
    url = 'https://api.mnemonic.no/pdns/v3/search'

    headers = {
        'Host' : 'api.mnemonic.no',
        'User-Agent' : ua,
        'Accept' : 'application/json',
        'Accept-Language' : 'en-US,en;q=0.5',
        'Accept-Encoding' : 'gzip, deflate',
        'Referer' : 'https://passivedns.mnemonic.no/',
        'Content-Type' : 'application/json',
        'Origin' : 'https://passivedns.mnemonic.no',
        'Connection' : 'close',
        'Content-Length' : '190'
    }

    payload = {
        'query': ip,
        'aggregateResult': 'true',
        'includeAnonymousResults': 'true',
        'rrClass': [],
        'rrType': [],
        'customerID': [],
        'tlp': [],
        'offset': 0,
        'limit': 25
    }

    r = requests.post(url, data = json.dumps(payload), headers = headers, verify = False)
    r_json = r.json()

    response_code = r_json['responseCode']

    if r.status_code != 200 or int(response_code) != 200:
        error('Server responded with HTTP code ' + str(r.status_code) + '.')
        sys.exit(1)

    fqdns = []

    for data in r_json['data']:
        last_ts = int(str(data['lastSeenTimestamp'])[:10])
        curr_ts = calendar.timegm(time.gmtime())
        diff_ts = 31536000 # exactly one year

        if (curr_ts - last_ts) < diff_ts:
            fqdns.append(data['query'])

    return fqdns

def get_useragent(rnd):
    # default User Agent
    ua = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'

    if rnd:
        try:
            f_rua = str(Path(__file__).resolve().parent) + '/browsers.txt'
            lines = open(f_rua).read().splitlines()

            return random.choice(lines)
        except FileNotFoundError:
            return ua
    else:
        return ua

def print_domains(ip, source, ua, output = None):
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        error('IP address is not valid.')
        sys.exit(1)

    try:
        rv = str(resolver.query(reversename.from_address(ip), 'PTR')[0])[:-1]
    except resolver.NXDOMAIN:
        rv = "- none -"
    except resolver.NoAnswer:
        rv = "- no answer -"
    except resolver.Timeout:
        rv = "- timeout -"

    print('[+] IP:         ' + colored(ip, 'white', attrs = ['bold']))
    print('[+] Rev. DNS:   ' + colored(rv, 'white', attrs = ['bold']))
    print('[+] Source:     ' + colored(source, 'yellow', attrs = ['bold']))
    print('[+] User Agent: ' + colored(ua, 'white', attrs = ['bold']))

    fqdns = globals()['from_' + source](ip, ua)
    count = len(fqdns)

    if count > 0:
        n = colored(str(count), 'green')
        print('[+] Found ' + n + ' domains:')

        if output is not None:
            f_output = open(output, 'a')

        fqdns.sort()

        for fqdn in fqdns:
            print(colored(fqdn, 'green'))

            if output is not None:
                print(fqdn, file = f_output)

        if output is not None:
            f_output.close()
    else:
        print('[+] No domains found for IP ' + colored(ip, 'white', attrs = ['bold']) + ', sorry.')

    print()

def main(argv):
    parser = argparse.ArgumentParser(prog = 'pared.py')
    group = parser.add_mutually_exclusive_group(required = True)
    group.add_argument('-i', '--ip', help = 'single IP address')
    group.add_argument('-s', '--subnet', help = 'subnet in CIDR notation')
    group.add_argument('-f', '--file', help = 'file containing a list of IP addresses')
    parser.add_argument('-o', '--output', help = 'save output to file')
    parser.add_argument('-r', '--rua', action='store_true', help = 'random user agent')
    parser.add_argument('--source', choices = ['hackertarget', 'mnemonic'], default = 'hackertarget', help = 'source of data ("hackertarget" is the default)')
    args = parser.parse_args()

    ip = args.ip
    subnet = args.subnet
    file = args.file
    output = args.output
    ua = get_useragent(args.rua)
    source = args.source

    logo()

    if ip is not None:
        print_domains(ip, source, ua, output)
    elif subnet is not None:
        try:
            for ip in IPv4Network(subnet):
                print_domains(ip, source, ua, output)
        except ipaddress.AddressValueError:
            error('Invalid subnet.')
        except ipaddress.NetmaskValueError:
            error('Invalid subnet.')
    elif file is not None:
        with open(file) as reader:
            for line in reader:
                print_domains(line.strip(), source, ua, output)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    main(sys.argv[1:])
