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

def is_valid_domain(domain):
    pattern = re.compile(r"^(?!:\/\/)([a-zA-Z0-9-_]+(\.[a-zA-Z0-9-_]+)+.*)$")
    if pattern.match(domain):
        return True
    return False

def filter_data(data):
    if data is None:
        return None

    filtered_data = {
        "Hostname": data.get("hostname"),
        "Type": data.get("type"),
        "Classification": data.get("classification"),
        "Tag": data.get("tag"),
        "Creation Time": data.get("creation_time"),
        "Modification Time": data.get("modification_time"),
        "Blacklist": data.get("blacklist", []),
    }
    
    boolean_fields = {
        "Is IoT Threat": data.get("is_iot_threat"),
        "Is Alive": data.get("is_alive"),
        "Is CNC": data.get("is_cnc"),
        "Is Distributing Malware": data.get("is_distributing_malware"),
        "Is Mining Pool": data.get("is_mining_pool"),
        "Is Storing Phishing": data.get("is_storing_phishing"),
        "Is Phishing": data.get("is_phishing")
    }

    for field, value in boolean_fields.items():
        if value:
            filtered_data[field] = True

    return filtered_data

def parse_args(args):
    domain = None
    full_data = False
    domain_file = None
    help = "usage: ./maltiverse.py <hostname> [-h] [-f] --file==[FILE]\n\nAn API script to gather data from https://maltiverse.com/\n\noptional arguments:\n  -h, --help      Show this help message and exit.\n  -f,             Retrieve the API full data.\n  --file==[FILE]  Full path to a test file containing a domain on each line."

    for arg in args:
        if arg == "--help" or arg == "-h":
            print(help)
            sys.exit(0)
        elif is_valid_domain(arg):
            domain = arg
        elif arg == '-f':
            full_data = True
        elif arg.startswith("--file="):
            domain_file = arg.split("=", 1)[1]
        elif arg.startswith('-'):
            print(f"Error: Unknown flag {arg}")
            print(help)
            sys.exit(1)
        else:
            print(f"Error: Unknown input {arg}")
            print(help)
            sys.exit(1)
    
    return domain, full_data, domain_file

try:
    domain, full_data, domain_file = parse_args(sys.argv[1:])

    if not domain and not domain_file:
        domain = input("Enter your domain address here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if domain_file:
        with open(domain_file, 'r') as file:
            ips = [line.strip() for line in file if is_valid_domain(line.strip())]
    else:
        ips = [domain]

    for domain in ips:
        if not is_valid_domain(domain):
            print(f"{domain} is not a valid domain address")
            continue
    
        url = f'https://api.maltiverse.com/hostname/{domain}'

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