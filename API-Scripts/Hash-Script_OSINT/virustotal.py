#!/bin/python3

import requests
import os
import sys
import json
import re
from dotenv import load_dotenv
from datetime import datetime

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

def filter_data(data, hash):
    if data is None:
        return None
    
    section_data = {}

    if section == "":
        attributes = data.get("data", {}).get("attributes")
        date = attributes.get("last_analysis_date")
        date = datetime.fromtimestamp(date).strftime('%Y-%m-%d')

        section_data["General"] = {
            "Hash": hash,
            "Name": attributes.get("meaningful_name"),
            "Last Analysis Date": date,
            "Tags": attributes.get("tags"),
            "Size": attributes.get("size"),
            "Harmless": attributes.get("last_analysis_stats", {}).get("harmless"),
            "Malicious": attributes.get("last_analysis_stats", {}).get("malicious"),
            "Suspicious": attributes.get("last_analysis_stats", {}).get("suspicious"),
            "Timeout": attributes.get("last_analysis_stats", {}).get("timeout"),
            "Undetected": attributes.get("last_analysis_stats", {}).get("undetected"),
            "Threat Label": attributes.get("popular_threat_classification", {}).get("suggested_threat_label")
        }

    elif section == "/behaviour_summary":
        section_data["Behaviour Summary"] = {
            "Hash": hash,
            "Command Executions": data.get("data").get("command_executions", []),
            "Processes Injected": data.get("data").get("processes_injected", []),
            "IP Traffic": data.get("data").get("ip_traffic", []),
            "DNS Lookups": data.get("data").get("dns_lookups", []),
            "TLS": data.get("data").get("tls", []),
            "Processes": {
                "Processes Tree": data.get("data").get("processes_tree", []),
                "Processes Created": data.get("data").get("processes_created", []),
                "Processes Terminated": data.get("data").get("processes_terminated", []),
            },
            "Files": {
                "Files Opened": data.get("data").get("files_opened", []),
                "Files Written": data.get("data").get("files_written", []),
                "Files Deleted": data.get("data").get("files_deleted", []),
                "Files Dropped": data.get("data").get("files_dropped", []),
            },
            "Services": {
                "Services Opened": data.get("data").get("services_opened", []),
                "Services Created": data.get("data").get("services_created", []),
                "Services Stopped": data.get("data").get("services_stopped", []),
            },
            "Tags": data.get("data").get("tags", []),
            "Modules Loaded": data.get("data").get("modules_loaded", []),
            "Registry Keys Opened": data.get("data").get("registry_keys_opened", []),
            "Text Highlighted": data.get("data").get("text_highlighted", []),
            "MITRE Attack Techniques": data.get("data").get("mitre_attack_techniques", []),
            "Attack Techniques": data.get("data").get("attack_techniques", [])
        }


    elif section == "/behaviours":
        section_data["Behaviours"] = {
            "Hash": hash,
            "Sandboxes Count": data.get("meta", 0),
            "Sandboxes": [{
            "Snadbox Name": attributes.get("attributes").get("sandbox_name", {}),
            "Command Executions": attributes.get("attributes").get("command_executions", []),
            "Processes Injected": attributes.get("attributes").get("processes_injected", []),
            "IP Traffic": attributes.get("attributes").get("ip_traffic", []),
            "DNS Lookups": attributes.get("attributes").get("dns_lookups", []),
            "TLS": attributes.get("attributes").get("tls", []),
            "Processes": {
                "Processes Tree": attributes.get("attributes").get("processes_tree", []),
                "Processes Created": attributes.get("attributes").get("processes_created", []),
                "Processes Terminated": attributes.get("attributes").get("processes_terminated", []),
            },
            "Files": {
                "Files Opened": attributes.get("attributes").get("files_opened", []),
                "Files Written": attributes.get("attributes").get("files_written", []),
                "Files Deleted": attributes.get("attributes").get("files_deleted", []),
                "Files Dropped": attributes.get("attributes").get("files_dropped", []),
            },
            "Services": {
                "Services Opened": attributes.get("attributes").get("services_opened", []),
                "Services Created": attributes.get("attributes").get("services_created", []),
                "Services Stopped": attributes.get("attributes").get("services_stopped", []),
            },
            "Tags": attributes.get("attributes").get("tags", []),
            "Modules Loaded": attributes.get("attributes").get("modules_loaded", []),
            "Registry Keys Opened": attributes.get("attributes").get("registry_keys_opened", []),
            "Text Highlighted": attributes.get("attributes").get("text_highlighted", []),
            "MITRE Attack Techniques": attributes.get("attributes").get("mitre_attack_techniques", []),
            "Attack Techniques": attributes.get("attributes").get("attack_techniques", [])
            }
            for attributes in data.get("data", [])]
        }

    section_data.update(section_data)

    return section_data

def parse_args(args):
    hash = None
    full_data = False
    hash_file = None
    sections = []
    help = (
        "usage: ./virustotal.py <hash> [-h] [-f] [-a] [-g] [-s] [-b] --file==[FILE]\n\n"
        "An API script to gather data from https://www.virustotal.com/\n\n"
        "optional arguments:\n"
        "  -h, --help      Show this help message and exit.\n"
        "  -f              Retrieve the API full data.\n"
        "  -a              Retrieve all sections data.\n"
        "  -g              Retrieve general data (Default).\n"
        "  -s              Retrieve behavior summary data.\n"
        "  -b              Retrieve all behavior data.\n"
        "  --file==[FILE]  Full path to a test file containing a hash or IDs on each line."
    )

    section_map = {
        'g': "",
        's': "/behaviour_summary",
        'b': "/behaviours",
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
    
    return hash, full_data, hash_file, sections

def fetch_data(hash, section):
    try:
        url = f"https://www.virustotal.com/api/v3/files/{hash}{section}"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        print(response.json())

try:
    hash, full_data, hash_file, sections = parse_args(sys.argv[1:])
    sections = sections or [""]

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
            data = fetch_data(hash, section)
            if data is None:
                break
            elif full_data:
                print(format_data(data))
            else:
                filtered_response = filter_data(data, hash)
                print(format_data(filtered_response))

except KeyboardInterrupt:
    print("\nProcess interrupted by user.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
