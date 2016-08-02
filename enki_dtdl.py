#!/usr/bin/python

# ENKI_DTDL
# Python Directory Traversal / Directory Listing program
# Note that there is no check to know if the target is up (we don't care)
# Written by Youssef - Toufik
# ENKI - 2016

# requirement.txt
# pip install requests netaddr


import requests
from netaddr import IPNetwork, AddrFormatError
import subprocess

subprocess.call('clear', shell=True)
debug = False
timeout = 1

def portrange(lp):
    if "-" in lp:
        return xrange(int(lp.split("-")[0]), int(lp.split("-")[1]))
    if "," in lp:
        return lp.split(",")
    if "" in lp:
        return list((80, 443))
    else:
        return list(int(lp))


# Check for available http service on port
def checkport(host, port):
    target = str(host) + ':' + str(port)
    try:
        if debug:
            print "[+] GET " + 'http://' + target
        requests.get("http://" + target, timeout=timeout)
        return "http"
    except KeyboardInterrupt:
        return exit(0)
    except:
        try:
            if debug:
                print "[+] GET " + 'https://' + target
            requests.get("https://" + target, timeout=timeout)
            return "https"
        except:
            return None


def dtdl(httpdalive, dico):
    with open(dico) as f:
        for path in f:
            for host in httpdalive:
                path = path.strip()
                code = str(requests.get(host + "/" + path).status_code)
                if "404" != code:
                    print host + "/" +  path + "/" + " " + code


def main():
    inputhost = list()
    hosts = list()
    httpdalive = list()

    inputd = raw_input("[*] Enable verbose mode (Yes/No): ")
    debug = True if inputd in "Yes" else False
    input1 = raw_input("[*] Enter the IP address or subnet address or the URL of the target (leave blank to use a list of host): ")
    inputhost.append(input1)

    if input1 in "":
        input11 = raw_input("[*] Enter the filename containing ip or url: ")
        with open(input11) as filename:
            for input1 in filename:
                inputhost.append(input1.strip())

    if debug:
        print "[+] Host to scan : " + str(inputhost)
    input2 = raw_input("[*] Enter single port or min-max ports (blank for default): ")
    input3 = raw_input("[*] Enter dictionary file: ")

    for input1 in inputhost:
        try:
            for ip in IPNetwork(input1):
                hosts.append(ip)
        except AddrFormatError:
            hosts.append(str(input1))

    for host in hosts:
        for port in portrange(input2):
            check = str(checkport(host, port))
            if check in ["http", "https"]:
                target = str(check) + "://" + str(host) + ":" + str(port)
                httpdalive.append(target)
    if debug:
        print "[+] Hosts alive :" + str(httpdalive)
    dtdl(httpdalive, input3)

# Main
if __name__=="__main__":
    main()
