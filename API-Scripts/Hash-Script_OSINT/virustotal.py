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

base_url = "https://www.virustotal.com/api/v3"

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
    
    attributes = data.get("data", {}).get("attributes", {})
    date = attributes.get("date")
    date = datetime.fromtimestamp(date).strftime('%Y-%m-%d')

    filtered_data = {
        "Hash": data.get("meta", {}).get("url_info", {}).get("hash"),
        "Date": date,
        "Harmless": attributes.get("stats",{}).get("harmless", 0),
        "Malicious": attributes.get("stats",{}).get("malicious", 0),
        "Suspicious": attributes.get("stats",{}).get("suspicious", 0),
        "Undetected": attributes.get("stats",{}).get("undetected", 0),
        "Timeout": attributes.get("stats",{}).get("timeout", 0),
        "File Info": data.get("meta", {}).get("file_info", {})
    }
    return filtered_data

def parse_args(args):
    hash = None
    full_data = False
    hash_file = None
    help = "usage: ./virustotal.py <hash|id> [-h] [-f] --file==[FILE]\n\nAn API script to gather data from https://www.virustotal.com/\n\noptional arguments:\n  -h, --help      Show this help message and exit.\n  -f,             Retrieve the API full data.\n  --file==[FILE]  Full path to a test file containing an Hash or IDs on each line."
    analysis_id = None

    for arg in args:
        if arg == "--help" or arg == "-h":
            print(help)
            sys.exit(0)
        elif is_valid_hash(arg):
            hash = arg
        elif re.match(r'^u-[0-9a-f]{64}-[0-9]{10}$', arg):
            analysis_id = arg
        elif arg == '-f':
            full_data = True
        elif arg.startswith("--file="):
            hash_file = arg.split("=", 1)[1]
        elif re.search(r'^[a-f0-9]{5,}:', arg):
            print(f"{arg} is not a valid Hash")
            sys.exit(1)
        else:
            print(f"Error: Unknown flag {arg}\n")
            print(help)
            sys.exit(1)
    
    return hash, full_data, hash_file, analysis_id

def fetch_url_data(target):
    try:
        if is_valid_hash(target):
            payload = {"hash": target}
            response = requests.post(f"{base_url}/hashes", data=payload, headers=headers)
            response.raise_for_status()
            response = response.json()
            analysis_id = response.get("data", {}).get("id")
            print("Analysing the Hash...\n")
        else:
            analysis_id = target
        while True:
            response = requests.get(f"{base_url}/analyses/{analysis_id}", headers=headers)
            response.raise_for_status()
            data = response.json()
            if data.get("data", {}).get("attributes", {}).get("status") != "queued":
                return data
            sleep(5)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        print(response.json())

try:
    hash, full_data, hash_file, analysis_id = parse_args(sys.argv[1:])

    if not hash and not hash_file and not analysis_id:
        hash = input("Enter your Hash here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if hash_file:
        with open(hash_file, 'r') as file:
            hashes = [line.strip() for line in file if is_valid_hash(line.strip()) or re.match(r'^u-[0-9a-f]{64}-[0-9]{10}$', line.strip())]
    else:
        hashes = [hash]

    for hash in hashes:
        data = fetch_url_data(hash or analysis_id)
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
