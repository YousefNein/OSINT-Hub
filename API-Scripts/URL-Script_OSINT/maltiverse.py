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

def is_valid_url(url):
    pattern = re.compile(
        r'^(?:http|ftp)s?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(pattern, url) is not None

def filter_data(data):
    if data is None:
        return None

    filtered_data = {
        "URL" : data.get("ip_addr"),
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
    url = None
    full_data = False
    url_file = None
    help = "usage: ./maltiverse.py <url> [-h] [-f] --file==[FILE]\n\nAn API script to gather data from https://maltiverse.com/\n\noptional arguments:\n  -h, --help      Show this help message and exit.\n  -f,             Retrieve the API full data.\n  --file==[FILE]  Full path to a test file containing an URL on each line."

    for arg in args:
        if arg == "--help" or arg == "-h":
            print(help)
            sys.exit(0)
        elif is_valid_url(arg):
            url = arg
        elif arg == '-f':
            full_data = True
        elif arg.startswith("--file="):
            url_file = arg.split("=", 1)[1]
        elif re.search(r'^https?:', arg):
            print(f"{arg} is not a valid IPv4 address")
            sys.exit(1)
        else:
            print(f"Error: Unknown flag {arg}\n")
            print(help)
            sys.exit(1)
    
    return url, full_data, url_file

try:
    url, full_data, url_file = parse_args(sys.argv[1:])

    if not url and not url_file:
        url = input("Enter your URL here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if url_file:
        with open(url_file, 'r') as file:
            urls = [line.strip() for line in file if is_valid_url(line.strip())]
    else:
        urls = [url]

    for url in urls:
        if not is_valid_url(url):
            print(f"{url} is not a valid IPv4 address")
            continue
    
        url = f'https://api.maltiverse.com/url/{url}'

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