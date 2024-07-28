#!/bin/python3

import requests
import json
import re
import sys
from dotenv import load_dotenv

load_dotenv()


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
    
    filtered_data = {
        "URL": data.get("url"),
        "URLHaus Reference": data.get("urlhaus_reference"),
        "URL Status": data.get("url_status"),
        "Host": data.get("host"),
        "Date Added": data.get("date_added"),
        "Last Online": data.get("last_online"),
        "Threat": data.get("threat"),
        "Blacklists": data.get("blacklists"),
        "Takedown Time (seconds)": data.get("takedown_time_seconds"),
        "Tags": data.get("tags"),
        "Payloads": []
    }

    for payload in data.get("payloads", []):
        filtered_payload = {
            "First Seen": payload.get("firstseen"),
            "Filename": payload.get("filename"),
            "File Type": payload.get("file_type"),
            "Signature": payload.get("signature"),
            "URLHaus Download": payload.get("urlhaus_download"),
            "VirusTotal": payload.get("virustotal")
        }
        filtered_data["Payloads"].append(filtered_payload)
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
        elif arg.startswith('-'):
            print(f"Error: Unknown flag {arg}")
            print(help)
            sys.exit(1)
        else:
            print(f"Error: Unknown input {arg}")
            print(help)
            sys.exit(1)
    
    return url, full_data, url_file

def fetch_data(url):
    try:
        payload = {'url' : url}
        response = requests.post(f"https://urlhaus-api.abuse.ch/v1/url", data=payload)
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
        data = fetch_data(url)
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

