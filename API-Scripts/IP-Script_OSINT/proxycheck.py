#!/bin/python3

import requests
import os
import sys
import re
import json
from dotenv import load_dotenv

load_dotenv()

api_key = os.environ.get("PROXY_CHECK")

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

    keys = list(data.keys())
    if len(keys) < 2:
        return None
    ip_key = keys[1]
    ip_data = data.get(ip_key, {})

    filtered_data = {
        "IP": ip_key,
        "Network": ip_data.get('range'),
        "ISP": ip_data.get('provider'),
        "Hostname": ip_data.get('hostname'),
        "Organisation": ip_data.get('organisation'),
        "Country": ip_data.get('country'),
        "City": ip_data.get('city'),
        "Proxy": ip_data.get('proxy'),
        "Type": ip_data.get('type'),
        "Risk": ip_data.get('risk')
    }

    return filtered_data

def parse_args(args):
    ip = None
    full_data = False
    ip_file = None
    help = "usage: ./proxycheck.py <ip> [-h] [-f] --file==[FILE]\n\nAn API script to gather data from https://proxycheck.io/\n\noptional arguments:\n  -h, --help      Show this help message and exit.\n  -f,             Retrieve the API full data.\n  --file==[FILE]  Full path to a test file containing an IP address on each line."

    for arg in args:
        if arg == "--help" or arg == "-h":
            print(help)
            sys.exit(0)
        elif is_valid_ipv4(arg):
            ip = arg
        elif arg == '-f':
            full_data = True
        elif arg.startswith("--file="):
            ip_file = arg.split("=", 1)[1]
        elif arg.startswith('-'):
            print(f"Error: Unknown flag {arg}")
            print(help)
            sys.exit(1)
        else:
            print(f"Error: Unknown input {arg}")
            print(help)
            sys.exit(1)
    
    return ip, full_data, ip_file

try:
    ip, full_data, ip_file = parse_args(sys.argv[1:])

    if not ip and not ip_file:
        ip = input("Enter your IP address here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if ip_file:
        with open(ip_file, 'r') as file:
            ips = [line.strip() for line in file if is_valid_ipv4(line.strip())]
    else:
        ips = [ip]

    for ip in ips:
        if not is_valid_ipv4(ip):
            print(f"{ip} is not a valid IPv4 address")
            continue

        url = f"https://proxycheck.io/v2/{ip}?key={api_key}&vpn=1&asn=1&cur=0&risk=1&port=1&seen=1"

        response = requests.get(url=url)
        response.raise_for_status()
        parsed = json.loads(response.text)

        if full_data:
            print(format_data(parsed))
        else:
            filtered_response = filter_data(parsed)
            print(format_data(filtered_response))
    
except KeyboardInterrupt:
    print("\nProcess interrupted by user.")
except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
    print(response.json())
except Exception as e:
    print(f"An unexpected error occurred: {e}")
