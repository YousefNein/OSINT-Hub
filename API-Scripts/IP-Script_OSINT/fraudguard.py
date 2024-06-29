#!/bin/python3

import requests
import os
import sys
import re
import json
import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

load_dotenv()

username = os.environ.get("FRAUD_GUARD_USERNAME")
password = os.environ.get("FRAUD_GUARD_PASSWORD")

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
        "Country": data.get('country'),
        "City": data.get('city'),
        "Connection Type": data.get('connection_type'),
        "ISP": data.get('isp'),
        "Organization": data.get('asn_organization'),
        "AS Name": data.get('organization'),
        "First seen": data.get('discover_date'),
        "Threat": data.get('threat'),
        "Risk Level": data.get('risk_level')
    }

    return filtered_data

def parse_args(args):
    ip = None
    full_data = False

    for arg in args:
        if is_valid_ipv4(arg):
            ip = arg
        elif arg == '-f':
            full_data = True
        else:
            print(f"Error: Unknown flag {arg}")
            sys.exit(1)
    
    return ip, full_data

try:
    ip, full_data = parse_args(sys.argv[1:])

    if not ip:
        ip = input("Enter your IP address here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if not is_valid_ipv4(ip):
        print(f"{ip} is not a valid IPv4 address")
        sys.exit(1)
    
    url = f'https://api.fraudguard.io/v2/ip/{ip}'

    response = requests.get(url=url, verify=True, auth=HTTPBasicAuth(username=username, password=password))
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
