#!/bin/python3

import requests
import sys
import json
import re

def format_data(data):
    formatted_data = json.dumps(data, indent=4, sort_keys=False)
    return formatted_data

def is_valid_ipv4(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if pattern.match(ip):
        return all(0 <= int(part) < 256 for part in ip.split('.'))
    return False

def filter_data(data):
    if data is None:
        return None

def parse_args(args):
    ip = None
    rt = None

    for arg in args:
        if is_valid_ipv4(arg):
            ip = arg
        elif arg.startswith('rt='):
            rt = arg
        else:
            print(f"Error: Unknown flag {arg}")
            sys.exit(1)
    
    return ip, rt

try:
    ip, rt = parse_args(sys.argv[1:])

    if not ip:
        ip = input("Enter your IP address here:\n")

    if not rt:
        rt = input("Enter the query type (rt=1 for WHOIS, rt=2 for Passive DNS, rt=3 for URIs, rt=4 for Related Samples, rt=5 for SSL Certificates, rt=6 for Report tagging):\n")
        if not rt.startswith('rt='):
            print(f"Error: Invalid query type {rt}")
            sys.exit(1)

    if not is_valid_ipv4(ip):
        print(f"{ip} is not a valid IPv4 address")
        sys.exit(1)
    
    url = f"https://api.threatminer.org/v2/host.php?q={ip}&{rt}"

    response = requests.get(url=url)

    response.raise_for_status()
    parsed = json.loads(response.text)

    print(format_data(parsed))

except KeyboardInterrupt:
    print("\nProcess interrupted by user.")
except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
    print(response.json())
except Exception as e:
    print(f"An unexpected error occurred: {e}")
