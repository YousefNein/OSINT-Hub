#!/bin/python3

import requests
import os
import sys
import json
import re
from dotenv import load_dotenv

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

    report = data.get('data', {}).get('report', {})

    filtered_data = {
        "IP": report.get('ip'),
        "ISP": report.get('information', {}).get('isp'),
        "Hostname": report.get('information', {}).get('reverse_dns'),
        "Country": report.get('information', {}).get('country_name'),
        "City": report.get('information', {}).get('city_name'),
        "Risk Score": report.get('risk_score', {}).get('result'),
        "Blacklist Detections": report.get('blacklists', {}).get('detections'),
        "Blacklist Engines Count": report.get('blacklists', {}).get('engines_count'),
        "Blacklist Detection Rate": report.get('blacklists', {}).get('detection_rate'),
    }

    boolean_fields = {
        "Is Proxy": report.get('anonymity', {}).get('is_proxy'),
        "Is Web Proxy": report.get('anonymity', {}).get('is_webproxy'),
        "Is VPN": report.get('anonymity', {}).get('is_vpn'),
        "Is Hosting": report.get('anonymity', {}).get('is_hosting'),
        "Is Tor": report.get('anonymity', {}).get('is_tor')
    }

    for field, value in boolean_fields.items():
        if value:
            filtered_data[field] = True

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
    
    apivoid_key = os.getenv('API_VOID')
    if not apivoid_key:
        print("API key not found. Please set the API_VOID environment variable.")
        sys.exit(1)

    url = f"https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key={apivoid_key}&ip={ip}"

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
