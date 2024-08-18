#!/bin/python3

import requests
import os
import sys
import json
import re
from dotenv import load_dotenv
from time import sleep

load_dotenv()

headers = {
    'Content-Type': 'application/json',
    'API-Key': os.environ.get("URL_SCAN_API")
}

base_url = "https://urlscan.io/api/v1"

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
    
    page = data.get("page", {})
    verdicts = data.get("verdicts", {}).get("urlscan") or data.get("verdicts", {}).get("overall", {})
    if not verdicts:
        verdicts = {"hasVerdicts": False}

    filtered_data = {
        "URL": page.get("url"),
        "Domain": page.get("domain"),
        "IP": page.get("ip"),
        "Country": page.get("country"),
        "ASN Name": page.get("asnname"),
        "Verdicts Brand": verdicts.get("brands"),
        "Verdicts Category": verdicts.get("categories"),
        "Malicious": verdicts.get("malicious"),
        "Score": verdicts.get("score")
    }
    return filtered_data

def parse_args(args):
    url = None
    full_data = False
    url_file = None
    help = "usage: ./urlscan.py <url|uuid> [-h] [-f] --file=[FILE]\n\nAn API script to gather data from https://urlscan.io/\n\noptional arguments:\n  -h, --help      Show this help message and exit.\n  -f              Retrieve the API full data.\n  --file=[FILE]   Full path to a test file containing an URL on each line."
    uuid = None

    for arg in args:
        if arg == "--help" or arg == "-h":
            print(help)
            sys.exit(0)
        elif is_valid_url(arg):
            url = arg
        elif re.match(r'^[0-9a-f-]{36}$', arg):
            uuid = arg
        elif arg == '-f':
            full_data = True
        elif arg.startswith("--file="):
            url_file = arg.split("=", 1)[1]
        elif arg.startswith('-'):
            print(f"Error: Unknown flag {arg}")
            print(help)
            sys.exit(1)
        else:
            print(f"Error: Unknown input {arg}")
            print(help)
            sys.exit(1)
    
    return url, full_data, url_file, uuid

def fetch_data(target):
    try:
        if is_valid_url(target):
            payload = {"url": target, "visibility": "public"}
            response = requests.post(f"{base_url}/scan/", headers=headers, data=json.dumps(payload))
            response.raise_for_status()
            response = response.json()
            uuid = response.get("uuid")
            print("Analysing the URL...\n")
        else:
            uuid = target
        while True:
            response = requests.get(f"{base_url}/result/{uuid}/", headers=headers)
            data = response.json()
            if response.status_code == 404 and data.get("message") == "Scan is not finished yet":
                sleep(5)
            elif response.status_code == 200:
                return data
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        print(response.json())

try:
    url, full_data, url_file, uuid = parse_args(sys.argv[1:])

    if not url and not url_file and not uuid:
        url = input("Enter your URL here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if url_file:
        with open(url_file, 'r') as file:
            urls = [line.strip() for line in file if is_valid_url(line.strip()) or re.match(r'^[0-9a-f-]{36}$', line.strip())]
    else:
        urls = [url]

    for url in urls:
        data = fetch_data(url or uuid)
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
