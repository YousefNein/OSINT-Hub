#!/bin/python3

import requests
import os
import sys
import json
import re
import hashlib
from dotenv import load_dotenv

load_dotenv()

api_key = os.environ.get("MALTIVERSE")

headers = { 
    'Authorization':'Bearer ' + api_key 
}

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
        "IP Address": data.get("ip_addr"),
        "URL": data.get("url"),
        "Classification": data.get("classification"),
        "Creation Time": data.get("creation_time"),
        "Last Online Time": data.get("last_online_time"),
        "Modification Time": data.get("modification_time"),
        "Tags": data.get("tag", []),
        "Blacklists": data.get("blacklist", [])
    }
    
    boolean_fields = {
        "Is Alive": data.get("is_alive"),
        "Is CNC": data.get("is_cnc"),
        "Is Distributing Malware": data.get("is_distributing_malware"),
        "Is IoT Threat": data.get("is_iot_threat"),
        "Is Phishing": data.get("is_phishing")
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
        elif arg.startswith('-'):
            print(f"Error: Unknown flag {arg}")
            print(help)
            sys.exit(1)
        else:
            print(f"Error: Unknown input {arg}")
            print(help)
            sys.exit(1)
    
    return url, full_data, url_file

def fetch_data(url_checksum):
    try:
        url = f'https://api.maltiverse.com/url/{url_checksum}'
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return None

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
        url_checksum = hashlib.sha256(url.encode("utf-8")).hexdigest()
        data = fetch_data(url_checksum)

        if data is None:
            break
        if full_data:
            print(format_data(data))
        else:
            filtered_response = filter_data(data)
            print(format_data(filtered_response))

except KeyboardInterrupt:
    print("\nProcess interrupted by user.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")