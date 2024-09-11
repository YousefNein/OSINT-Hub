#!/bin/python3

import requests
import os
import sys
import json
import re
from dotenv import load_dotenv

load_dotenv()

headers = {
    'accept': 'application/json',
    'api-key': os.environ.get("HYBRID_ANALYSIS"),
    'Content-Type': 'application/x-www-form-urlencoded'
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

    for entry in data:    
        filtered_data = {
            "Hash": hash,
            "Malware Info": {
                "Family": entry.get("vx_family"),
                "Threat Level": entry.get("threat_level"),
                "Verdict": entry.get("verdict"),
                "Threat Score": entry.get("threat_score"),
            },
            "Environment Info": {
                "Description": entry.get("environment_description"),
                "Size": entry.get("size"),
                "Type": entry.get("type"),
                "Submission Name": entry.get("submit_name"),
                "Start Time": entry.get("analysis_start_time"),
            },
            "AV Detection": {
                "AV Detect": entry.get("av_detect"),
            },
            "CrowdStrike AI": {
                "Executable Process Memory Analysis": entry.get("crowdstrike_ai", {}).get("executable_process_memory_analysis"),
                "Analysis Related URLs": entry.get("crowdstrike_ai", {}).get("analysis_related_urls"),
            },
            "Submissions": entry.get("submissions"),
            "Classification Tags": entry.get("classification_tags"),
            "Tags": entry.get("tags"),
            "URL Analysis": entry.get("url_analysis"),
            "DLL Characteristics": entry.get("dll_characteristics"),
            "OS Version": {
                "Major": entry.get("major_os_version"),
                "Minor": entry.get("minor_os_version"),
            },
            "Processes": entry.get("processes"),
            "Domains": entry.get("domains"),
            "Hosts": entry.get("hosts"),
            "Compromised Hosts": entry.get("compromised_hosts"),
            "Total Processes": entry.get("total_processes"),
            "Signatures": entry.get("signatures")
        }

        return filtered_data

def parse_args(args):
    hash = None
    full_data = False
    hash_file = None
    help_text = "usage: ./hybrid_analysis.py <hash> [-h] [-f] --file=[FILE]\n\nAn API script to perform quick scan on a Hash from https://www.hybrid-analysis.com/\n\noptional arguments:\n  -h, --help      Show this help message and exit.\n  -f              Retrieve the API full data.\n  --file=[FILE]   Full path to a text file containing URLs or IDs, one per line."

    for arg in args:
        if arg == "--help" or arg == "-h":
            print(help_text)
            sys.exit(0)
        elif is_valid_hash(arg):
            hash = arg
        elif arg == '-f':
            full_data = True
        elif arg.startswith("--file="):
            hash_file = arg.split("=", 1)[1]
        else:
            print(f"Error: Unknown flag {arg}\n")
            print(help_text)
            sys.exit(1)
    
    return hash, full_data, hash_file

def fetch_data(hash):
    try:
        payload = {"hash": hash}
        response = requests.post(f"https://www.hybrid-analysis.com/api/v2/search/hash", headers=headers, data=payload)
        response.raise_for_status()
        data = response.json()
        return data

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        print(response.json())
try:
    hash, full_data, hash_file = parse_args(sys.argv[1:])

    if not hash and not hash_file:
        hash = input("Enter your Hash or ID here:\n")
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
