#!/bin/python3

import requests
import sys
import json
import re
import os
from dotenv import load_dotenv

load_dotenv()

api_key = os.environ.get('PULSEDIVE_API_KEY')

headers = {
    'Accept': 'application/json'
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
    
    filtered_data = {
        "IP": data.get("indicator"),
        "Whois": {
            "Organization": data.get("properties", {}).get("geo", {}).get("org", {}),
            "ISP": data.get("properties", {}).get("geo", {}).get("isp", {}),
            "Country": data.get("properties", {}).get("geo", {}).get("countrycode", {}),
            "Emails": data.get("properties", {}).get("whois", {}).get("++email", [])
            },
        "Risk": data.get("risk"),
        "Riskfactors": [rf.get("description") for rf in data.get("riskfactors", [])],
        "Threats": [threat.get("name") for threat in data.get("threats", [])],
        "Feeds": [
            {
                "Feed Name": feed.get("name"),
                "Category": feed.get("category")
            } for feed in data.get("feeds", [])
            ],
        "attributes": {
        "port": data.get("attributes", {}).get("port", []),
        "protocol": data.get("attributes", {}).get("protocol", []),
        "technology": data.get("attributes", {}).get("technology", [])
    },
        "Redirects": data.get("redirects", {}),
        "Headers": data.get("properties", {}).get("http", {}),
        "Banners": data.get("properties", {}).get("banners", {})
    }

    return filtered_data

def parse_args(args):
    ip = None
    full_data = False
    ip_file = None
    help = """
usage: ./pulsedive.py <ip> [-h] [-f] --file==[FILE]

An API script to gather data from https://pulsedive.com/

optional arguments:
  -h, --help      Show this help message and exit.
  -f              Retrieve the API full data.
  --file==[FILE]  Full path to a test file containing an IP address on each line.
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
        response = requests.get(f'https://pulsedive.com/api/info.php?indicator={ip}&limit=10&pretty=1&key={api_key}', headers=headers)
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
