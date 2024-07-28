#!/bin/python3

import requests
import os
import sys
import json
import re
from dotenv import load_dotenv

load_dotenv()

headers = {
    'Accept': 'application/json',
    "Key": os.environ.get("GREY_NOISE")
}

def format_data(data):
    for key in ['cve', 'tags', 'CVE', 'Tags', 'User Agents', 'Target Countries']:
        if key in data and isinstance(data[key], list):
            data[key] = ','.join(data[key])

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

    filtered_data = {
        # "IP": data.get('ip'), # Uncomment for the enterprise version
        # "Country": data.get('metadata', {}).get('country'),
        # "AS Name": data.get('metadata', {}).get('organization'),
        # "Category": data.get('metadata', {}).get('category'),
        # "Hostname": data.get('metadata', {}).get('rdns'),
        # "OS": data.get('metadata', {}).get('os'),
        # "First seen": data.get('first_seen'),
        # "Last seen": data.get('last_seen'),
        # "Actor": data.get('actor'),
        # "Classification": data.get('classification'),
        # "CVE": data.get('cve', []),
        # "Tags": data.get('tags', []),
        # "URI Paths": data.get('raw_data', {}).get('web',{}).get('paths', []),
        # "User Agents": data.get('raw_data', {}).get('web',{}).get('useragents', []),
        # "Target Countries": data.get('metadata', {}).get('destination_country_codes')
        "IP": data.get('ip'), # Uncomment for the community version
        "Noise": data.get('noise'),
        "Riot": data.get('riot'),
        "Classification": data.get('classification'),
        "Name": data.get('name'),
        "Link": data.get('link'),
        "Last seen": data.get('last_seen')
    }

    boolean_fields = [
        "spoofable", "bot", "vpn", "tor"
    ]

    for field in boolean_fields:
        if data.get(field, False):
            filtered_data[field] = True
            if field == "vpn":
                filtered_data["vpn_service"] = data.get("vpn_service", "N/A")

    return filtered_data

def parse_args(args):
    ip = None
    full_data = False
    ip_file = None
    help = "usage: ./greynoise.py <ip> [-h] [-f] --file==[FILE]\n\nAn API script to gather data from https://www.greynoise.io/\n\noptional arguments:\n  -h, --help      Show this help message and exit.\n  -f,             Retrieve the API full data.\n  --file==[FILE]  Full path to a test file containing an IP address on each line."

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
   
        url = f"https://api.greynoise.io/v3/community/{ip}" #Free version
        # url = f"https://api.greynoise.io/v2/noise/context/{ip}" # Enterprise API

        response = requests.get(url, headers=headers)
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
