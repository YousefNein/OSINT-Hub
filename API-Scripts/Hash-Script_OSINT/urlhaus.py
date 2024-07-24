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
        "Hash": data.get("hash"),
        "URLHaus Reference": data.get("urlhaus_reference"),
        "Hash Status": data.get("url_status"),
        "Host": data.get("host"),
        "Date Added": data.get("date_added"),
        "Last Online": data.get("last_online"),
        "Threat": data.get("threat"),
        "Blacklists": data.get("blacklists"),
        "Takedown Time (seconds)": data.get("takedown_time_seconds"),
        "Tags": data.get("tags"),
        "Payloads": []
    }

    for payload in data.get("payloads", []):
        filtered_payload = {
            "First Seen": payload.get("firstseen"),
            "Filename": payload.get("filename"),
            "File Type": payload.get("file_type"),
            "Signature": payload.get("signature"),
            "URLHaus Download": payload.get("urlhaus_download"),
            "VirusTotal": payload.get("virustotal")
        }
        filtered_data["Payloads"].append(filtered_payload)
    return filtered_data

def parse_args(args):
    hash = None
    full_data = False
    hash_file = None
    help = "usage: ./urlhaus.py <hash> [-h] [-f] --file=[FILE]\n\nAn API script to gather data from https://urlhaus.abuse.ch/\n\noptional arguments:\n  -h, --help      Show this help message and exit.\n  -f,             Retrieve the API full data.\n  --file=[FILE]   Full path to a test file containing an Hash on each line."

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
        elif re.search(r'^[a-f0-9]{5,}:', arg):
            print(f"{arg} is not a valid Hash")
            sys.exit(1)
        else:
            print(f"Error: Unknown flag {arg}\n")
            print(help)
            sys.exit(1)
    
    return hash, full_data, hash_file

def fetch_url_data(hash):
    try:
        payload = {'hash' : hash}
        response = requests.post(f"https://urlhaus-api.abuse.ch/v1/hash", data=payload)
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
        data = fetch_url_data(hash)
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

