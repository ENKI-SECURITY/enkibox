!/usr/bin/env python

# ENKI_DTDL
# Python Directory Traversal / Directory Listing program
# Note that there is no check to know if the target is up (we don't care)
# Written by Youssef - Toufik
# ENKI - 2016

from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

import subprocess
import sys
from datetime import datetime
from time import strftime

subprocess.call('clear', shell=True)

# Scan host function
def scanhost():
    try:
        ip = raw_input("[*] Enter the subnet address or IP address of the target: ")
        int(low_port) = raw_input("[*] Enter Minimum port number to start from (leave blank for default all 65535): ")

        if not low_port:
            high_port = 65535
        else:
            int(high_port) = raw_input("[*] Enter Highest port number to end at: ")

        try:
            if low_port >= 0 and high_port >= 0 and high_port >= low_port:
                pass
            else:
                print "\n[!] Invalid range of ports"
                print "\n[!] Exiting"
                sys.exit(1)

        except Exception:
            print "\n[!] An error has occured"
            print "\n[!] Exiting"
            sys.exit(1)

        except KeyboardInterrupt:
            print "\n[*] User interruption caughted"
            print "\n[*] Exiting"
            sys.exit(1)

    ports = range(int(lowport), int(high_port)+1)
    schedule = datetime.now()
    SYNACK = 0x12
    RSTACK = 0x14

    srcport = RandShort()
    conf.verb = 0
    SYNACKP = sr1(IP(dest = ip)/TCP(sport = srcport, dport = ports, flags = "S"))

# Check for available http service on any port
def httpservicecheck(svports):

# Execute the DT/DL
def dtdl(urllst, ports):

# Main
