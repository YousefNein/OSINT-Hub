#!/bin/python3

import requests
import os
import sys
import json
import re
from dotenv import load_dotenv
from time import sleep
from urllib.parse import quote

load_dotenv()

headers = {
    'accept': 'application/json',
    'api-key': os.environ.get("HYBRID_ANALYSIS"),
    'Content-Type': 'application/x-www-form-urlencoded'
}

base_url = "https://www.hybrid-analysis.com/api/v2/quick-scan"

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

    scanner = data.get("scanners_v2")

    filtered_data = {
        "URL" : url or analysis_id,
        "CrowdStrike": scanner.get("crowdstrike_ml"),
        "MetaDefender": scanner.get("metadefender"),
        "VirusTotal": scanner.get("virustotal"),
        "URLScan": scanner.get("urlscan_io"),
        "ScamAdvider": scanner.get("scam_adviser"),
        "CleanDNS": scanner.get("clean_dns"),
        "BeforeAI": scanner.get("before_ai"),
        "Criminal IP": scanner.get("criminal_ip"),  
        "Whitelist": data.get("whitelist", []),
        "Reports Count": len(data.get("reports", []))
    }
    for key, value in filtered_data.items():
        if isinstance(value, dict):
            value.pop("name", None)
            value.pop("progress", None)

    return filtered_data


def parse_args(args):
    url = None
    full_data = False
    url_file = None
    help_text = "usage: ./hybrid_analysis.py <url|id> [-h] [-f] --file=[FILE]\n\nAn API script to perform quick scan on a URL from https://www.hybrid-analysis.com/\n\noptional arguments:\n  -h, --help      Show this help message and exit.\n  -f              Retrieve the API full data.\n  --file=[FILE]   Full path to a text file containing URLs or IDs, one per line."
    analysis_id = None

    for arg in args:
        if arg == "--help" or arg == "-h":
            print(help_text)
            sys.exit(0)
        elif re.match(r'^[0-9a-f]{24}$', arg):
            analysis_id = arg
        elif is_valid_url(arg):
            url = arg
        elif arg == '-f':
            full_data = True
        elif arg.startswith("--file="):
            url_file = arg.split("=", 1)[1]
        else:
            print(f"Error: Unknown flag {arg}\n")
            print(help_text)
            sys.exit(1)
    
    return url, full_data, url_file, analysis_id

def fetch_data(target):
    try:
        if is_valid_url(target):
            payload = f"scan_type=all&url={quote(target)}"
            response = requests.post(f"{base_url}/url", headers=headers, data=payload)
            response.raise_for_status()
            response = response.json()
            analysis_id = response.get("id")
            print("Analysing the URL...\n")
        else:
            analysis_id = target
        while True:
            response = requests.get(f'{base_url}/{analysis_id}', headers=headers)
            response.raise_for_status()
            data = response.json()
            if data.get("finished") == True:
                return data
            sleep(5)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        print(response.json())
try:
    url, full_data, url_file, analysis_id = parse_args(sys.argv[1:])

    if not url and not url_file and not analysis_id:
        url = input("Enter your URL or ID here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if url_file:
        with open(url_file, 'r') as file:
            urls = [line.strip() for line in file if is_valid_url(line.strip()) or re.match(r'^[0-9a-f]{24}$', line.strip())]
    else:
        urls = [url]

    for url in urls:
        data = fetch_data(url or analysis_id)
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
