#!/bin/python3

import requests
import os
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

def is_valid_url(url):
    pattern = re.compile(
        r'^(?:http|ftp)s?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(pattern, url) is not None

def filter_data(data):
    if data is None:
        return None

    tags = set()
    target = set()
    pulses = data.get("pulse_info", {}).get("pulses", [])

    for pulse in pulses:
        tags.update(pulse.get("tags", []))
        target.update(pulse.get("targeted_countries", []))

    section_data = {}

    if section == "general":
        section_data["General"] = {
        "URL": url,
        "Country": data.get("country_name"),
        "AS Name": data.get("asn"),
        "Reputation": data.get("reputation"),
        "Related Pulses": data.get("pulse_info", {}).get("count", 0),
        "Tags Count": len(tags),
        "Related Tags": list(tags),
        "Targeted Countries": list(target)
    }
    elif section == "malware":
        section_data["Malware"] = {
            "URL": url,
            "Data": data.get("data", []),
            "Count": data.get("count", 0),
            "Size": data.get("size", 0),
        }

    elif section == "reputation":
        section_data["Reputation"] = {
            "URL": url,
            "Reputation": data.get("reputation"),
        }

    elif section == "passive_dns":
        section_data["DNS"] = {
            "URL": url,
            "Passive DNS": [
        {        
                "URL Address": entry.get("address"),
                "Hostname": entry.get("hostname"),
                "Record Type": entry.get("record_type"),
                "AS Name": entry.get("asn"),
         
         }
            for entry in data.get("passive_dns", []) ],
            "Count": data.get("count", 0),
        }

    elif section == "geo":
        section_data["Geo"] = {
            "URL": url,
            "ASN": data.get("asn"),
            "Country": data.get("country_name"),
            "City": data.get("city"),
            "Region": data.get("region"),
            "Latitude": data.get("latitude"),
            "Longitude": data.get("longitude"),
        }

    elif section == "url_list":
        section_data["URL List"] = {
            "URL": url,
            "URL List": [
            {
                "URL": entry.get("url"),
                "Domain": entry.get("domain"),
                "Hostname": entry.get("hostname"),
                "Result": {
                "URL Worker": {"HttpCode": entry.get("httpcode", 0)}
                }
            }
            for entry in data.get("url_list", []) ],
            "Count": data.get("count", 0),
        }

    elif section == "http_scans":
        section_data["HTTP Scan"] = {
            "URL": url,
            "Data": [
                f"{entry.get('name')} : {entry.get('value')}"
                for entry in data.get("data", [])
            ],
            "Count": data.get("count", 0),
        }

    section_data.update(section_data)

    return section_data

def parse_args(args):
    url = None
    full_data = False
    url_file = None
    sections = []
    help = "usage: ./alienvault.py <url> [-h] [-f] [-a] [-g] [-c] [-r] [-d] [-m] [-u] [-s] --file==[FILE]\n\nAn API script to gather data from https://otx.alienvault.com/\n\noptional arguments:\n  -h, --help     Show this help message and exit.\n  -f,             Retrieve the API full data.\n  -a              Retrieve all data.\n  -g              Retrieve general data. (Default)\n  -c              Retrieve Geo data.\n  -r              Retrieve Reputation data.\n  -m              Retrieve Malware data.\n  -d              Retrieve Passive DNS data.\n  -u              Retrieve URL list data.\n  -s              Retrieve HTTP scans data.\n  --file==[FILE]  Full path to a test file containing a domain name on each line."
    
    section_map = {
        'g': 'general',
        'c': "geo",
        'r': "reputation",
        'm': "malware",
        'd': "passive_dns",
        'u': "url_list",
        's': "http_scans"
    }

    for arg in args:
        if arg == "--help" or arg == "-h":
            print(help)
            sys.exit(0)
        elif is_valid_url(arg):
            url = arg
        elif arg.startswith("--file="):
            url_file = arg.split("=", 1)[1]
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
        elif re.search(r'^https?:', arg):
            print(f"{arg} is not a valid IPv4 address")
            sys.exit(1)
        else:
            print(f"Error: Unknown input {arg}\n")
            print(help)
            sys.exit(1)
    
    return url, full_data, url_file, sections

try:
    url, full_data, url_file, sections = parse_args(sys.argv[1:])
    sections = sections or ["general"]

    if not url and not url_file:
        url = input("Enter your URL here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if url_file:
        with open(url_file, 'r') as file:
            urls = [line.strip() for line in file if is_valid_url(line.strip())]
    else:
        urls = [url]

    for url in urls:
        if not is_valid_url(url):
            print(f"{url} is not a valid IPv4 address")
            continue

        for section in sections:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{url}/{section}"

            response = requests.get(url, headers=headers)
            response.raise_for_status()
            parsed = json.loads(response.text)

            if full_data:
                print(format_data(parsed))
            else:
                filtered_response = filter_data(parsed)
                print(format_data(filtered_response))

except KeyboardInterrupt:
    print("\nProcess interrupted by user.")
except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
    print(response.json())
except Exception as e:
    print(f"An unexpected error occurred: {e}")
