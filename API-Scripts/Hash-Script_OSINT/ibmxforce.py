#!/bin/python3

import requests
import os
import sys
import json
import re
import base64
from dotenv import load_dotenv
from urllib.parse import quote
from datetime import datetime
from time import sleep

load_dotenv()

api_key = os.environ.get("IBM_XFORCE_API_KEY")
api_key_password = os.environ.get("IBM_XFORCE_API_PASS")
credentials = f"{api_key}:{api_key_password}"
encoded_credentials = base64.b64encode(credentials.encode()).decode()

headers = {
    'accept': 'application/json',
    'Authorization': f"Basic {encoded_credentials}"
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

    filtered_data = {
        "Hash": data.get("malware", {}).get("hash"),
        "Hash Type": data.get("malware", {}).get("type"),
        "Source": data.get("malware", {}).get("origins", {}).get("external", {}).get("source"),
        "Platform": data.get("malware", {}).get("origins", {}).get("external", {}).get("platform"),
        "FirstSeen": data.get("malware", {}).get("origins", {}).get("external", {}).get("firstSeen"),
        "LastSeen": data.get("malware", {}).get("origins", {}).get("external", {}).get("lastSeen"),
        "MalwareType": data.get("malware", {}).get("origins", {}).get("external", {}).get("malwareType"),
        "Malware Families": data.get("malware", {}).get("origins", {}).get("external", {}).get("family"),
        "Risk": data.get("malware", {}).get("risk"),
        "DetectionCoverage": data.get("malware", {}).get("origins", {}).get("external", {}).get("detectionCoverage"),
    }
    
    return filtered_data

def parse_args(args):
    hash = None
    full_data = False
    hash_file = None
    help = "usage: ./ibm_xforce.py <hash> [-h] [-f] --file=[FILE]\n\nAn API script to gather data from https://exchange.xforce.ibmcloud.com/\n\noptional arguments:\n  -h, --help      Show this help message and exit.\n  -f,             Retrieve the API full data.\n  -r              Retrieve Hash report data. (Default)\n  -m              Retrieve Malware data.\n  --file=[FILE]  Full path to a test file containing a Hash on each line."

    for arg in args:
        if arg == "--help" or arg == "-h":
            print(help)
            sys.exit(0)
        elif is_valid_hash(arg):
            hash = arg
        elif arg.startswith("--file="):
            hash_file = arg.split("=", 1)[1]
        elif arg.startswith('-'):
            for flag in arg[1:]:
                if flag == 'f':
                    full_data = True
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
        response = requests.get(f"https://api.xforce.ibmcloud.com/malware/{hash}", headers=headers)
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
