#!/bin/python3

import requests
import os
import sys
import json
import re
import base64
from dotenv import load_dotenv
from urllib.parse import quote
from datetime import datetime
from time import sleep

load_dotenv()

api_key = os.environ.get("IBM_XFORCE_API_KEY")
api_key_password = os.environ.get("IBM_XFORCE_API_PASS")
credentials = f"{api_key}:{api_key_password}"
encoded_credentials = base64.b64encode(credentials.encode()).decode()

headers = {
    'accept': 'application/json',
    'Authorization': f"Basic {encoded_credentials}"
}

base_url_xf = "https://api.xforce.ibmcloud.com"

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

    section_data = {}    
    result = data.get("result", {})

    if section == "url":    
        section_data["Report"] = {
            "URL" : result.get("url"),
            'Name': result.get('application', {}).get('name'),
            'Score': result.get('score') or result.get('application', {}).get('score'),
            'URLs': result.get('url'),
            'Application': result.get('application', {}),
            'Categories': result.get('cats'),
            'Category Descriptions': result.get('application', {}).get('categoryDescriptions'),
            'Tags': result.get('tags', [])
        }
    elif section == "url/malware":    
        section_data["Malware"] = {
            "URL" : url,
            "Malware": [data.get("malware", [])],
            "Count": data.get("count", 0),
        }

    section_data.update(section_data)

    return section_data

def parse_args(args):
    url = None
    full_data = False
    url_file = None
    sections = []
    help = "usage: ./ibm_xforce.py <url> [-h] [-f] --file=[FILE]\n\nAn API script to gather data from https://exchange.xforce.ibmcloud.com/\n\noptional arguments:\n  -h, --help      Show this help message and exit.\n  -f,             Retrieve the API full data.\n  -r              Retrieve URL report data. (Default)\n  -m              Retrieve Malware data.\n  --file=[FILE]  Full path to a test file containing a URL on each line."

    section_map = {
        'r': "url",
        'm': "url/malware"
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
        elif re.search(r'^https?:', arg):
            print(f"{arg} is not a valid URL")
            sys.exit(1)
        else:
            print(f"Error: Unknown flag {arg}\n")
            print(help)
            sys.exit(1)
    
    return url, full_data, url_file, sections

def fetch_url_data(target):
    try:
        encoded_url = quote(target)
        response = requests.get(f"{base_url_xf}/{section}/{encoded_url}", headers=headers)
        response.raise_for_status()
        data = response.json()
        return data

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        print(response.json())

try:
    url, full_data, url_file, sections = parse_args(sys.argv[1:])
    sections = sections or ["url"]

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
