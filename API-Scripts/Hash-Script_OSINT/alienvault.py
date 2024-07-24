#!/bin/python3

import requests
import sys
import json
import re
from dotenv import load_dotenv

load_dotenv()

headers = {
    'Accept': 'application/json'
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

def filter_data(data, section):
    if data is None:
        return None

    tags = set()
    references = set()
    targeted = set()
    mal_fam = set()
    attack_id = set()
    pulses = data.get("pulse_info", {}).get("pulses", [])

    for pulse in pulses:
        tags.update(pulse.get("tags", []))
        references.update(pulse.get("references", []))
        targeted.update(pulse.get("targeted_countries", []))
        for malware_display_name in pulse.get("malware_families", []):
            mal_fam.add(malware_display_name.get("display_name"))
        for attck_display_name in pulse.get("attack_ids", []):
            attack_id.add(attck_display_name.get("display_name"))

    section_data = {}

    if section == "general":
        section_data["General"] = {
            "Hash": data.get("indicator"),
            "Type": data.get("type"),
            "Tags Count": len(tags),
            "Related Tags": list(tags),
            "Targeted Countries": list(targeted),
            "References": list(references),
            "Malware Families" : list(mal_fam),
            "Attack ID" : list(attack_id)
        }

    elif section == "url_list":
        section_data["Hash List"] = {
            "Hash": hash,
            "Domain": data.get("net_loc"),
            "City": data.get("city"),
            "Country": data.get("country_name"),
            "Hash List": [
            {
                "Result": {
                "Hash Worker": {
                    "IP": entry.get("result", {}).get("urlworker", {}).get("ip"),
                    "File Type": entry.get("result", {}).get("urlworker", {}).get("filetype"),
                    "Headers": entry.get("result", {}).get("urlworker", {}).get("http_response"),
                    "HTTP Status": entry.get("httpcode", 0)
                    }
                }
            }
            for entry in data.get("url_list", []) if entry.get("result", None) is not None
            ],

        }

    section_data.update(section_data)

    return section_data

def parse_args(args):
    hash = None
    full_data = False
    hash_file = None
    sections = []
    help = "usage: ./alienvault.py <hash> [-h] [-f] [-a] [-g] [-s] --file==[FILE]\n\nAn API script to gather data from https://otx.alienvault.com/\n\noptional arguments:\n  -h, --help     Show this help message and exit.\n  -f,             Retrieve the API full data.\n  -a              Retrieve all sections data.\n  -g              Retrieve general data. (Default)\n  -s              Retrieve hash analysis data.\n  --file==[FILE]  Full path to a test file containing a Hash on each line."
    
    section_map = {
        'g': 'general',
        's': "analysis"
    }

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
                elif flag == 'a':
                    sections = set(section_map.values())
                elif flag in section_map:
                    sections.append(section_map[flag])
                else:
                    print(f"Error: Unknown flag -{flag}")
                    print(help)
                    sys.exit(1)
        elif re.search(r'^[a-f0-9]{5,}:', arg):
            print(f"{arg} is not a valid hash")
            sys.exit(1)
        else:
            print(f"Error: Unknown input {arg}\n")
            print(help)
            sys.exit(1)
    
    return hash, full_data, hash_file, sections

def fetch_url_data(hash, section):
    try:
        response = requests.post(f"https://otx.alienvault.com/api/v1/indicators/file/{hash}/{section}")
        response.raise_for_status()
        data = response.json()
        return data

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        print(response.json())

try:
    hash, full_data, hash_file, sections = parse_args(sys.argv[1:])
    sections = sections or ["general"]

    if not hash and not hash_file:
        hash = input("Enter your Hash here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if hash_file:
        with open(hash_file, 'r') as file:
            hashes = [line.strip() for line in file if is_valid_hash(line.strip())]
    else:
        hashes = [hash]

    for hash in hashes:
        for section in sections:
            data = fetch_url_data(hash, section)
            if data is None:
                break
            elif full_data:
                print(format_data(data))
            else:
                filtered_response = filter_data(data, section)
                print(format_data(filtered_response))

except KeyboardInterrupt:
    print("\nProcess interrupted by user.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
