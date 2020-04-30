# PaReD

**PaReD** is a simple Python script that tries to determine one or more FQDNs of a given IP address using passive reverse DNS lookups.

**Usage:**
```
usage: pared.py [-h] (-i IP | -s SUBNET | -f FILE) [-o OUTPUT]

optional arguments:
  -h, --help            show this help message and exit
  -i IP, --ip IP        single IP address
  -s SUBNET, --subnet SUBNET
                        subnet in CIDR notation
  -f FILE, --file FILE  file containing a list of IP addresses
  -o OUTPUT, --output OUTPUT
                        save output to file
```
