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
def defhost():
    try:
        ip = raw_input("[*] Enter the subnet address or IP address of the target: ")
        
        rep = raw_input("[*] For port scanning range type 'r' or 's' for single port scanning: ")
        
        if rep in "s":
            int(single_port) = raw_input("[*] SINGLE PORT MODE - Enter the port number you wish to scan: ")
            
        else if rep in "r":
            int(low_port) = raw_input("[*] Enter Minimum port number to start from: ")
            int(high_port) = raw_input("[*] Enter Highest port number to end at: ")
            
        else if not rep:
            print "\n[*] Scanning all 65535 ports from 80"
            all_ports = 65535

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

# Check for available http service on any port
def httpservicecheck(svports):
    schedule = datetime.now()
    
# Execute the DT/DL
def dtdl(urllst, dict):

# Main
