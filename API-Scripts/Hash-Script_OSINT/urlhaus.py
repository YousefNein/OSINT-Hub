#!/bin/python3

import requests
import json
import re
import sys
from dotenv import load_dotenv

load_dotenv()

headers = {
    "Content-Type": "application/json"
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
    help = "usage: ./urlhaus.py <url> [-h] [-f] --file=[FILE]\n\nAn API script to gather data from https://urlhaus.abuse.ch/\n\noptional arguments:\n  -h, --help      Show this help message and exit.\n  -f,             Retrieve the API full data.\n  --file=[FILE]   Full path to a test file containing an URL on each line."

    for arg in args:
        if arg == "--help" or arg == "-h":
            print(help)
            sys.exit(0)
        elif is_valid_url(arg):
            url = arg
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
    
    return url, full_data, url_file

def fetch_url_data(url):
    try:
        payload = {'url' : url}
        response = requests.get(f"https://urlhaus-api.abuse.ch/v1/url//scan/", headers=headers, data=payload)
        response.raise_for_status()
        data = response.json()
        return data

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        print(response.json())

try:
    url, full_data, url_file = parse_args(sys.argv[1:])

    if not url and not url_file:
        url = input("Enter your URL here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if url_file:
        with open(url_file, 'r') as file:
            urls = [line.strip() for line in file if is_valid_url(line.strip())]
    else:
        urls = [url]

    for url in urls:
        data = fetch_url_data(url)
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

