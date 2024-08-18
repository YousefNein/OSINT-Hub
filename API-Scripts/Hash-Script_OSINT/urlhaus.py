#!/bin/python3

import requests
import json
import re
import sys
from dotenv import load_dotenv

load_dotenv()


def format_data(data):
    formatted_data = json.dumps(data, indent=4, sort_keys=False)
    return formatted_data

def is_valid_hash(hash):
    patterns = {
        'md5_hash': r'^[a-f0-9]{32}$',
        'sha256_hash': r'^[a-f0-9]{64}$',
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
        "File Type" : data.get("file_type"),
        "File Size" : data.get("file_size"),
        "Signature" : data.get("signature"),
        "First Seen" : data.get("firstseen"),
        "Last Seen" : data.get("lastseen"),
        "URL Count" : data.get("url_count"),
        "URLHaus Download" : data.get("urlhaus_download"),
        "VirusTotal": data.get("virustotal"),
        "URLs": [
            {
                "Filename" : entry.get("filename"),
                "URL" : entry.get("url"),
                "URL Status" : entry.get("url_status"),
                "First Seen" : entry.get("firstseen"),
                "Last Seen" : entry.get("lastseen"),
                "URLHaus Reference": entry.get("urlhaus_reference")
            }
        for entry in data.get("urls")]
    }

    return filtered_data

def parse_args(args):
    hash = None
    full_data = False
    hash_file = None
    help = "usage: ./urlhaus.py <hash> [-h] [-f] --file=[FILE]\n\nAn API script to gather data from https://urlhaus.abuse.ch/\n\noptional arguments:\n  -h, --help      Show this help message and exit.\n  -f              Retrieve the API full data.\n  --file=[FILE]   Full path to a test file containing an Hash on each line."

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
            print(f"Error: Unknown input {arg}. Only use MD5 or SHA256")
            print(help)
            sys.exit(1)
    
    return hash, full_data, hash_file

def fetch_data(hash):
    hashType = is_valid_hash(hash)
    try:
        payload = {hashType : hash}
        response = requests.post(f"https://urlhaus-api.abuse.ch/v1/payload", data=payload)
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

