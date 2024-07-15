#!/bin/python3

import requests
import os
import sys
import json
import re
from dotenv import load_dotenv
from datetime import datetime
from time import sleep

load_dotenv()

headers = {
    'Accept': 'application/json',
    'x-apikey': os.environ.get("VIRUS_TOTAL_API")
}

base_url = "https://www.virustotal.com/api/v3"

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
    
    attributes = data.get("data", {}).get("attributes", {})
    date = attributes.get("date")
    date = datetime.fromtimestamp(date).strftime('%Y-%m-%d')

    filtered_data = {
        "URL": data.get("meta", {}).get("url_info", {}).get("url"),
        "Date": date,
        "Harmless": attributes.get("stats",{}).get("harmless", 0),
        "Malicious": attributes.get("stats",{}).get("malicious", 0),
        "Suspicious": attributes.get("stats",{}).get("suspicious", 0),
        "Undetected": attributes.get("stats",{}).get("undetected", 0),
        "Timeout": attributes.get("stats",{}).get("timeout", 0),
        "File Info": data.get("meta", {}).get("file_info", {})
    }
    return filtered_data

def parse_args(args):
    url = None
    full_data = False
    url_file = None
    help = "usage: ./virustotal.py <url or id> [-h] [-f] --file==[FILE]\n\nAn API script to gather data from https://www.virustotal.com/\n\noptional arguments:\n  -h, --help      Show this help message and exit.\n  -f,             Retrieve the API full data.\n  --file==[FILE]  Full path to a test file containing an URL or IDs on each line."
    analysis_id = None

    for arg in args:
        if arg == "--help" or arg == "-h":
            print(help)
            sys.exit(0)
        elif is_valid_url(arg):
            url = arg
        elif re.match(r'^u-[0-9a-f]', arg):
            analysis_id = arg
        elif arg == '-f':
            full_data = True
        elif arg.startswith("--file="):
            url_file = arg.split("=", 1)[1]
        elif re.search(r'^https?:', arg):
            print(f"{arg} is not a valid URL")
            sys.exit(1)
        else:
            print(f"Error: Unknown flag {arg}\n")
            print(help)
            sys.exit(1)
    
    return url, full_data, url_file, analysis_id

def fetch_url_data(target):
    try:
        if is_valid_url(target):
            payload = {"url": target}
            response = requests.post(f"{base_url}/urls", data=payload, headers=headers)
            response.raise_for_status()
            response = response.json()
            analysis_id = response.get("data", {}).get("id")
            print("Analysing the URL...\n")
        else:
            analysis_id = target
        while True:
            response = requests.get(f"{base_url}/analyses/{analysis_id}", headers=headers)
            response.raise_for_status()
            data = response.json()
            if data.get("data", {}).get("attributes", {}).get("status") != "queued":
                return data
            sleep(5)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        print(response.json())

try:
    url, full_data, url_file, analysis_id = parse_args(sys.argv[1:])

    if not url and not url_file and not analysis_id:
        url = input("Enter your URL here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if url_file:
        with open(url_file, 'r') as file:
            urls = [line.strip() for line in file if is_valid_url(line.strip()) or re.match(r'^[0-9a-f]{24}$', line.strip())]
    else:
        urls = [url]

    for url in urls:
        data = fetch_url_data(url or analysis_id)
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
