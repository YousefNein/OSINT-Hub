#!/bin/python3

import requests
import sys
import json
import re
import os
from dotenv import load_dotenv
from time import sleep

load_dotenv()

api_key = os.environ.get("SPAMHAUS_API_KEY")

headers = { 
    'Authorization':'Bearer ' + api_key 
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

    section_data = {}

    if section == "last":
        section_data["Last"] = {
            "URL": data.get("url", {}),
            "ID": data.get("id", {}),
            "Status" : data.get("status"),
            "Payload" : data.get("payload")
        }

    elif section == "history":
        section_data["History"] = {
            "URL": data.get("url", {}),
            "ID": data.get("id", {}),
            "Status" : data.get("status"),
            "Payload" : data.get("payload"),
            "Events" : data.get("events")
        }

    section_data.update(section_data)

    return section_data

def parse_args(args):
    url = None
    full_data = False
    url_file = None
    sections = []
    help = "usage: ./spamhaus.py <url> [-h] [-f] [-a] [-l] [-t] --file==[FILE]\n\nAn API script to gather data from https://spamhaus.org\n\noptional arguments:\n  -h, --help     Show this help message and exit.\n  -f              Retrieve the API full data.\n  -a              Retrieve all sections data.\n  -l              Retrieve the last status of a URL and the last payload observed. (Default)\n  -t              Retrieve the last events occurring on a specific URL.\n  --file==[FILE]  Full path to a test file containing a URL on each line."
    
    section_map = {
        'l': 'last',
        't': "history"
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
        if is_valid_url(url):
            payload = json.dumps({"url": url})
            response = requests.post(f"https://api.spamhaus.org/api/intel/v2/byobject/url/{section}", data=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            return data

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        print(response.json())

try:
    url, full_data, url_file, sections = parse_args(sys.argv[1:])
    sections = sections or ["last"]

    if not url and not url_file:
        url = input("Enter your URL here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if url_file:
        with open(url_file, 'r') as file:
            urls = [line.strip() for line in file if is_valid_url(line.strip()) or re.match(r'^u-[0-9a-f]{64}-[0-9]{10}$', line.strip())]
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
                filtered_response = filter_data(data)
                print(format_data(filtered_response))

except KeyboardInterrupt:
    print("\nProcess interrupted by user.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
