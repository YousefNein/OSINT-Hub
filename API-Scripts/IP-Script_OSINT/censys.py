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
    'Authorization': os.environ.get("CENSYS_API")
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

    result = data.get('result', {})
    
    filtered_data = {
        "IP": result.get('ip'),
        "Country": result.get('location', {}).get('country'),
        "City": result.get('location', {}).get('city'),
        "Network": data["result"]["whois"]["network"]["cidrs"][0],
        "AS Name": result.get('whois',{}).get('organization', {}).get('name'),
        "Hostnames": result.get('dns', {}).get('names', []),
        "Tags": result.get('labels', [])
    }

    services = result.get('services', [])
    filtered_services = []

    for service in services:
        filtered_service = {
            "Service Name": service.get('service_name'),
            "Port": service.get('port'),
            "Software": service.get('software', [])[0] if service.get('software') else None
        }
        filtered_services.append(filtered_service)

    filtered_data["Services"] = filtered_services
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

    url = f"https://search.censys.io/api/v2/hosts/{ip}"

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
