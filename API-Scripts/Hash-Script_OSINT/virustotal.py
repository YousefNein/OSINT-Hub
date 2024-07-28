#!/bin/python3

import requests
import os
import sys
import json
import re
from dotenv import load_dotenv
from datetime import datetime
from time import sleep

load_dotenv()

headers = {
    'Accept': 'application/json',
    'x-apikey': os.environ.get("VIRUS_TOTAL_API")
}

def format_data(data):
    formatted_data = json.dumps(data, indent=4, sort_keys=False)
    return formatted_data
def is_valid_hash(hash):
    patterns = {
        'md5': r'^[a-f0-9]{32}$',
        'sha1': r'^[a-f0-9]{40}$',
        'sha256': r'^[a-f0-9]{64}$',
        'sha512': r'^[a-f0-9]{128}$'
    }

    for pattern in patterns.values():
        if re.match(pattern, hash, re.IGNORECASE):
            return True
    return False

def filter_data(data):
    if data is None:
        return None
    
    attributes = data.get("data", {}).get("attributes")
    date = attributes.get("last_analysis_date")
    date = datetime.fromtimestamp(date).strftime('%Y-%m-%d')

    filtered_data = {
        "Hash": hash,
        "Name" : attributes.get("meaningful_name"),
        "Last Analysis Date" : date,
        "Tags" : attributes.get("tags"),
        "Size" : attributes.get("size"),
        "Harmless" : attributes.get("last_analysis_stats", {}).get("harmless"),
        "Malicious" : attributes.get("last_analysis_stats", {}).get("malicious"),
        "Suspicious" : attributes.get("last_analysis_stats", {}).get("suspicious"),
        "Timeout" : attributes.get("last_analysis_stats", {}).get("timeout"),
        "Undetected" : attributes.get("last_analysis_stats", {}).get("undetected"),
        "Threat Label" : attributes.get("popular_threat_classification", {}).get("suggested_threat_label")
    }
    return filtered_data

def parse_args(args):
    hash = None
    full_data = False
    hash_file = None
    help = "usage: ./virustotal.py <hash|id> [-h] [-f] --file==[FILE]\n\nAn API script to gather data from https://www.virustotal.com/\n\noptional arguments:\n  -h, --help      Show this help message and exit.\n  -f,             Retrieve the API full data.\n  --file==[FILE]  Full path to a test file containing an Hash or IDs on each line."

    for arg in args:
        if arg == "--help" or arg == "-h":
            print(help)
            sys.exit(0)
        elif is_valid_hash(arg):
            hash = arg
        elif arg == '-f':
            full_data = True
        elif arg.startswith("--file="):
            hash_file = arg.split("=", 1)[1]
        elif arg.startswith('-'):
            print(f"Error: Unknown flag {arg}")
            print(help)
            sys.exit(1)
        else:
            print(f"Error: Unknown input {arg}")
            print(help)
            sys.exit(1)
    
    return hash, full_data, hash_file

def fetch_data(hash):
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/files/{hash}", headers=headers)
        response.raise_for_status()
        data = response.json()
        return data

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        print(response.json())

try:
    hash, full_data, hash_file = parse_args(sys.argv[1:])

    if not hash and not hash_file:
        hash = input("Enter your Hash here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if hash_file:
        with open(hash_file, 'r') as file:
            hashes = [line.strip() for line in file if is_valid_hash(line.strip())]
    else:
        hashes = [hash]

    for hash in hashes:
        data = fetch_data(hash)
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
