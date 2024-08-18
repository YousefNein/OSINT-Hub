#!/bin/python3

import requests
import os
import sys
import json
import re
from dotenv import load_dotenv
from datetime import datetime
load_dotenv()

headers = {
    'Accept': 'application/json',
    'x-apikey': os.environ.get("VIRUS_TOTAL_API")
}

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
    
    attributes = data.get("data", {}).get("attributes", {})
    last_analysis_stats = attributes.get("last_analysis_stats", {})
    last_analysis_date = attributes.get("last_analysis_date")
    if last_analysis_date is not None:
        last_analysis_date = datetime.fromtimestamp(last_analysis_date).strftime('%Y-%m-%d') 

    filtered_data = {
        "IP": data.get('data', {}).get('id'),
        "AS Name": attributes.get("as_owner"),
        "Country": attributes.get("country"),
        "Network": attributes.get("network"),
        "Reputation": attributes.get("reputation"),
        "Last Analysis": last_analysis_date,
        "Harmless": last_analysis_stats.get("harmless", 0),
        "Malicious": last_analysis_stats.get("malicious", 0),
        "Suspicious": last_analysis_stats.get("suspicious", 0),
        "Undetected": last_analysis_stats.get("undetected", 0),
        "Timeout": last_analysis_stats.get("timeout", 0)
    }
    return filtered_data

def parse_args(args):
    ip = None
    full_data = False
    ip_file = None
    help = "usage: ./virustotal.py <ip> [-h] [-f] --file==[FILE]\n\nAn API script to gather data from https://www.virustotal.com/\n\noptional arguments:\n  -h, --help      Show this help message and exit.\n  -f              Retrieve the API full data.\n  --file==[FILE]  Full path to a test file containing an IP address on each line."

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

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

        response = requests.get(headers=headers, url=url)
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
