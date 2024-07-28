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

def is_valid_hash(hash):
    patterns = {
        'md5': r'^[a-f0-9]{32}$',
        'sha1': r'^[a-f0-9]{40}$',
        'sha256': r'^[a-f0-9]{64}$',
        'sha512': r'^[a-f0-9]{128}$'
    }

    for hash_type, pattern in patterns.items():
        if re.match(pattern, hash, re.IGNORECASE):
            return hash_type
    return None

def filter_data(data):
    if data is None:
        return None

    filtered_data = {
        "Hash": hash,
        "Classification": data.get("classification"),
        "Creation Time": data.get("creation_time"),
        "Last Online Time": data.get("last_online_time"),
        "Modification Time": data.get("modification_time"),
        "Tags": data.get("tag", []),
        "Blacklists": data.get("blacklist", []),
        "File Name": data.get("filename", []),
        "File Type": data.get("filetype"),
        "Score": data.get("score"),
        "Process List": data.get("process_list", [])
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
    hash = None
    full_data = False
    hash_file = None
    help = "usage: ./maltiverse.py <hash> [-h] [-f] --file==[FILE]\n\nAn API script to gather data from https://maltiverse.com/\n\noptional arguments:\n  -h, --help      Show this help message and exit.\n  -f,             Retrieve the API full data.\n  --file==[FILE]  Full path to a test file containing an Hash on each line."

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
    hashType = is_valid_hash(hash)
    try:
        hash = f'https://api.maltiverse.com/sample/{hashType}/{hash}'
        response = requests.get(hash, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return None

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
        if full_data:
            print(format_data(data))
        else:
            filtered_response = filter_data(data)
            print(format_data(filtered_response))

except KeyboardInterrupt:
    print("\nProcess interrupted by user.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")