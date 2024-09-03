#!/bin/python3

import requests
import sys
import json
import re
import time

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
    if data is None or 'results' not in data:
        return None
    
    section_data = {}

    if section == "1":
        section_data["Meta Data"] = [
            {
            "Hash": hash,
            "MD5": entry.get("md5"),
            "SHA256": entry.get("sha256"),
            "SSDeep": entry.get("ssdeep"),
            "IMPHash": entry.get("imphash"),
            "File Name": entry.get("file_name"),
            "File Type": entry.get("file_type"),
            "Architecture": entry.get("architecture"),
            "Analyzed Date": entry.get("date_analysed")
            }
        for entry in data.get("results")
        ]
    elif section == "2":
        section_data["HTTP Traffic"] = [
            {
                "Domain": http_entry.get("domain"),
                "IP": http_entry.get("ip"),
                "HTTP Method": http_entry.get("method"),
                "URL": http_entry.get("url"),
                "User Agent": http_entry.get("user_agent"),
                "Port": http_entry.get("port")
            }
            for entry in data.get("results", []) for http_entry in entry.get("http_traffic", [])
        ]
    elif section == "3":
        section_data["Hosts"] = {
            "Domains": [
                {
                    "IP": domain_entry.get("ip"),
                    "Domain": domain_entry.get("domain")
                }
                for entry in data.get("results", []) for domain_entry in entry.get("domains", [])
            ],
            "Hosts": [
                host_entry
                for entry in data.get("results", []) for host_entry in entry.get("hosts", [])
            ]
        }

    elif section == "4":
        section_data["Mutants"] = [mutants_entry
            for entry in data.get("results", []) for mutants_entry in entry.get("mutants", [])
            ]
    elif section == "5":
        section_data["Registry keys"] = { "Hash": hash, "Regitery": data["results"]}
    elif section == "6":
        section_data["AV Detections"] = [
            {
                "Detection": av_entry.get("detection"),
                "Anti-Virus": av_entry.get("av")
            }
            for entry in data.get("results", []) for av_entry in entry.get("av_detections", [])
        ]

    elif section == "7":
        section_data["Report Tagging"] = [
            {
                "Hash": hash,
                "Filename": entry.get("filename"),
                "Year": entry.get("year"),
                "URL": entry.get("URL")
            }
            for entry in data["results"]
        ]
    else:
        section_data = data

    return section_data

def parse_args(args):
    hash = None
    full_data = False
    hash_file = None
    sections = []
    help = "usage: ./threatminer.py <hash> [-h] [-f] [-a] [-m] [-t] [-d] [-u] [-r] [-v] [-g] --file==[FILE]\n\nAn API script to gather data from https://www.threatminer.org/\n\noptional arguments:\n  -h, --help     Show this help message and exit.\n  -f             Retrieve the API full data.\n  -a             Retrieve all sections data.\n  -m             Retrieve Metadata.\n  -t             Retrieve HTTP traffic data.\n  -d             Retrieve Hosts (domains and hashs) data.\n  -u             Retrieve Mutants versions data.\n  -r             Retrieve Registry keys.\n  -v             Retrieve Anti-Virus detections data.\n  -g             Retrieve Report tagging data.\n  --file==[FILE] Full path to a test file containing an hash on each line."

    section_map = {
        'm': '1',
        't': "2",
        'd': "3",
        'u': "4",
        'r': "5",
        'v': "6",
        'g': "7"
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
                    sections = list(section_map.values())
                elif flag in section_map:
                    sections.append(section_map[flag])
                else:
                    print(f"Error: Unknown flag -{flag}")
                    print(help)
                    sys.exit(1)
        elif re.search(r'[0-9]{1,4}', arg):
            print(f"{arg} is not a valid IPv4 address")
            sys.exit(1)
        else:
            print(f"Error: Unknown input {arg}\n")
            print(help)
            sys.exit(1)
    
    return hash, full_data, hash_file, sections

def fetch_data(hash, section):
    try:
        url = f"https://api.threatminer.org/v2/sample.php?q={hash}&rt={section}"
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        return data

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        print(response.json())

try:
    hash, full_data, hash_file, sections = parse_args(sys.argv[1:])
    sections = sections or ["1"]

    if not hash and not hash_file:
        hash = input("Enter your hash address here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if hash_file:
        with open(hash_file, 'r') as file:
            hashes = [line.strip() for line in file if is_valid_hash(line.strip())]
    else:
        hashes = [hash]

    for hash in hashes:
        time.sleep(6)
        for section in sections:
            data = fetch_data(hash, section)
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
