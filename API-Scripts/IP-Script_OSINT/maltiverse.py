#!/bin/python3

import requests
import os
import sys
import json
import re
from dotenv import load_dotenv

load_dotenv()

api_key = os.environ.get("MALTIVERSE")

headers = { 
    'Authorization':'Bearer ' + api_key 
}

load_dotenv()

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

    filtered_data = {
        "IP" : data.get("ip_addr"),
        "AS Name": data.get("registrant_name"),
        "Country" : data.get("country_code"),
        "City": data.get('city'),
        "Network" : data.get("asn_cidr"),
        "Classification": data.get("classification"),
        "Creation Time": data.get("creation_time"),
    }
    
    boolean_fields = {
        "Is CDN": data.get("is_cdn"),
        "Is CNC": data.get("is_cnc"),
        "Is Distributing Malware": data.get("is_distributing_malware"),
        "Is Hosting": data.get("is_hosting"),
        "Is IoT Threat": data.get("is_iot_threat"),
        "Is Known Attacker": data.get("is_known_attacker"),
        "Is Known Scanner": data.get("is_known_scanner"),
        "Is Mining Pool": data.get("is_mining_pool"),
        "Is Open Proxy": data.get("is_open_proxy"),
        "Is Sinkhole": data.get("is_sinkhole"),
        "Is Tor Node": data.get("is_tor_node"),
        "Is VPN Node": data.get("is_vpn_node")
    }

    for field, value in boolean_fields.items():
        if value:
            filtered_data[field] = True

    return filtered_data

def parse_args(args):
    ip = None
    full_data = False
    ip_file = None
    help = "usage: ./maltiverse.py <ip> [-h] [-f] --file==[FILE]\n\nAn API script to gather data from https://maltiverse.com/\n\noptional arguments:\n  -h, --help      Show this help message and exit.\n  -f              Retrieve the API full data.\n  --file==[FILE]  Full path to a test file containing an IP address on each line."

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
    
        url = f'https://api.maltiverse.com/ip/{ip}'

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