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

#### TODO:
#### - add http://ptrarchive.com/tools/lookup2.htm?ip=8.8.8.8
#### - add https://api.hackertarget.com/reverseiplookup/?q=8.8.8.8

import argparse
import getopt
import ipaddress
import re
import requests
import signal
import sys
import urllib3
from ipaddress import IPv4Network
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

def print_domains(ip, output = None):
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        print(colored('ERROR!', 'red', attrs = ['reverse', 'bold']) + ' IP address is not valid.')
        sys.exit(1)

    print('[+] IP: ' + colored(ip, 'white', attrs = ['bold']))

    url = 'https://securitytrails.com/list/ip/' + ip
#    url = 'https://api.hackertarget.com/reverseiplookup/?q=' + ip
    ua = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'

    r = requests.get(url, headers = {'User-Agent': ua}, verify = False)
    fqdns = re.findall('dns\"\>(.*?)\<\/a\>', r.text)
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
    args = parser.parse_args()
    ip = args.ip
    subnet = args.subnet
    file = args.file
    output = args.output

    logo()

    if ip is not None:
        print_domains(ip, output)
    elif subnet is not None:
        try:
            for ip in IPv4Network(subnet):
                print_domains(ip, output)
        except ipaddress.AddressValueError:
            print(colored('ERROR!', 'red', attrs = ['reverse', 'bold']) + ' Invalid subnet.')
        except ipaddress.NetmaskValueError:
            print(colored('ERROR!', 'red', attrs = ['reverse', 'bold']) + ' Invalid subnet.')
    elif file is not None:
        with open(file) as reader:
            for line in reader:
                print_domains(line.strip(), output)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    main(sys.argv[1:])
