#!/bin/python3

import requests
import os
import sys
import json
import re
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv('API_VOID')

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

    report = data.get('data', {}).get('report', {})

    filtered_data = {
        "URL": report.get('url'),
        "ISP": report.get('information', {}).get('isp'),
        "Hostname": report.get('information', {}).get('reverse_dns'),
        "Country": report.get('information', {}).get('country_name'),
        "City": report.get('information', {}).get('city_name'),
        "Risk Score": report.get('risk_score', {}).get('result'),
        "Blacklist Detections": report.get('blacklists', {}).get('detections'),
        "Blacklist Engines Count": report.get('blacklists', {}).get('engines_count'),
        "Blacklist Detection Rate": report.get('blacklists', {}).get('detection_rate'),
    }

    boolean_fields = {
        "Is Proxy": report.get('anonymity', {}).get('is_proxy'),
        "Is Web Proxy": report.get('anonymity', {}).get('is_webproxy'),
        "Is VPN": report.get('anonymity', {}).get('is_vpn'),
        "Is Hosting": report.get('anonymity', {}).get('is_hosting'),
        "Is Tor": report.get('anonymity', {}).get('is_tor')
    }

    for field, value in boolean_fields.items():
        if value:
            filtered_data[field] = True

    return filtered_data

def parse_args(args):
    url = None
    full_data = False
    url_file = None
    help = "usage: ./apivoid.py <url> [-h] [-f] --file==[FILE]\n\nAn API script to gather data from https://www.apivoid.com/\n\noptional arguments:\n  -h, --help      Show this help message and exit.\n  -f,             Retrieve the API full data.\n  --file==[FILE]  Full path to a test file containing an URL on each line."
        
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
            print(f"{arg} is not a valid IPv4 address")
            sys.exit(1)
        else:
            print(f"Error: Unknown flag {arg}\n")
            print(help)
            sys.exit(1)
    
    return url, full_data, url_file

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
        if not is_valid_url(url):
            print(f"{url} is not a valid IPv4 address")
            continue
    
        url = f"https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key={api_key}&url={url}"
        response = requests.get(url=url)

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
