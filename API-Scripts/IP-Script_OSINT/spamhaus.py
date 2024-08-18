#!/bin/python3

import requests
import os
import sys
import json
import re
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

api_key = os.environ.get("SPAMHAUS_API_KEY")

headers = { 
    'Authorization':'Bearer ' + api_key 
}

load_dotenv()

def format_data(data):
    formatted_data = json.dumps(data, indent=4, sort_keys=False)
    return formatted_data

def is_valid_ipv4(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:\/\d{2})?$")
    if pattern.match(ip):
        return True
    return False

from datetime import datetime

def filter_data(data):
    if data is None or 'results' not in data:
        return None

    filtered_data = {}

    keys = ['ipaddress', 'cc', 'botname', 'heuristic', 'domain', 'dstport', 'detection', 'seen']

    for entry in data['results']:
        dataset_type = entry.get('dataset')

        if dataset_type not in filtered_data:
            filtered_data[dataset_type] = {key: set() for key in keys}

        for key in keys:
            value = entry.get(key)
            if value and value != 'N/A' and value != 'unknown':
                if key in ['seen', 'valid_until'] and isinstance(value, int):
                    value = datetime.fromtimestamp(value).strftime('%Y-%m-%d')
                if isinstance(value, list):
                    filtered_data[dataset_type][key].update(value)
                else:
                    filtered_data[dataset_type][key].add(value)

    cleaned_data = {}

    for dataset, attributes in filtered_data.items():
        cleaned_data[dataset] = {}
        for key, values in attributes.items():
            values = list(values)
            if len(values) == 1:
                cleaned_data[dataset][key] = values[0]
            elif len(values) > 0:
                cleaned_data[dataset][key] = values

    return cleaned_data


def parse_args(args):
    ip = None
    full_data = False
    ip_file = None
    help = """
usage: ./spamhaus.py <ip> [-h] [-f] --file==[FILE]

An API script to gather data from https://spamhaus.org/

optional arguments:
  -h, --help      Show this help message and exit.
  -f              Retrieve the API full data.
  --file==[FILE]  Full path to a test file containing an IP address on each line.

Dataset Information:
  SBL (Spamhaus Blocklist): lists IPs involved in spam, snowshoe spamming, bulletproof hosting, and hijacked space, useful for blocking spam senders and malicious URIs.  
  XBL (Exploits Block List): Lists IP addresses that are known to be involved in exploiting security vulnerabilities.
  CSS (Content Security System): Contains data about IP addresses involved in various security threats related to content.
  PBL (Policy Block List): Includes IP addresses that are not supposed to send email directly to the internet.
  BCL (Botnet Controller List): Contains IP addresses used exclusively for hosting botnet command and control (C&C) servers, designed to block all traffic to these dedicated C&C hosts.

  """
    
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

def fetch_data(ip):
    try:
        response = requests.get(f'https://api.spamhaus.org/api/intel/v1/byobject/cidr/ALL/listed/history/{ip}?limit=50', headers=headers)
        response.raise_for_status()
        data = response.json()
        return data

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        print(response.json())

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
        data = fetch_data(ip)
        if data is None:
            break
        elif full_data:
            print(format_data(data))
        else:
            filtered_response = filter_data(data)
            print(format_data(filtered_response))

except KeyboardInterrupt:
    print("\nProcess interrupted by user.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")