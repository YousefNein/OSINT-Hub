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

def is_valid_url(url):
    pattern = re.compile(
        r'^(?:http|ftp)s?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(pattern, url) is not None

def filter_data(data, section):
    if data is None:
        return None

    tags = set()
    references = set()
    pulses = data.get("pulse_info", {}).get("pulses", [])

    for pulse in pulses:
        tags.update(pulse.get("tags", []))
        references.update(pulse.get("references", []))

    section_data = {}

    if section == "general":
        section_data["General"] = {
            "URL": url,
            "Domain" : data.get("domain"),
            "Hostname" : data.get("hostname"),
            "Tags Count": len(tags),
            "Related Tags": list(tags),
            "References": list(references),
            "False Positive" : data.get("false_positive")
        }

    elif section == "url_list":
        section_data["URL List"] = {
            "URL": url,
            "Domain": data.get("net_loc"),
            "City": data.get("city"),
            "Country": data.get("country_name"),
            "URL List": [
            {
                "Result": {
                "URL Worker": {
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
    url = None
    full_data = False
    url_file = None
    sections = []
    help = "usage: ./alienvault.py <url> [-h] [-f] [-a] [-g] [-u] --file==[FILE]\n\nAn API script to gather data from https://otx.alienvault.com/\n\noptional arguments:\n  -h, --help     Show this help message and exit.\n  -f,             Retrieve the API full data.\n  -a              Retrieve all sections data.\n  -g              Retrieve general data. (Default)\n  -u              Retrieve URL list data.\n  --file==[FILE]  Full path to a test file containing a URL on each line."
    
    section_map = {
        'g': 'general',
        'u': "url_list"
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
            print(f"{arg} is not a valid URL")
            sys.exit(1)
        else:
            print(f"Error: Unknown input {arg}\n")
            print(help)
            sys.exit(1)
    
    return url, full_data, url_file, sections

def fetch_data(url, section):
    try:
        response = requests.post(f"https://otx.alienvault.com/api/v1/indicators/url/{url}/{section}")
        response.raise_for_status()
        data = response.json()
        return data

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        print(response.json())

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
        for section in sections:
            data = fetch_data(url, section)
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
