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

    section_data = {}

    if section == "":
        section_data["General"] = {
        "URL": data.get("meta", {}).get("url_info", {}).get("url"),
        "URL-ID": data.get("data").get("id"),
        "Date": date,
        "Harmless": attributes.get("stats",{}).get("harmless", 0),
        "Malicious": attributes.get("stats",{}).get("malicious", 0),
        "Suspicious": attributes.get("stats",{}).get("suspicious", 0),
        "Undetected": attributes.get("stats",{}).get("undetected", 0),
        "Timeout": attributes.get("stats",{}).get("timeout", 0),
        "File Info": data.get("meta", {}).get("file_info", {})
        }

    elif section == "behaviours":
        attributes = data.get("data", {}).get("attributes", {})
        section_data["Behaviours"] = {
            "Analysis Date": datetime.fromtimestamp(attributes.get("analysis_date", 0)).strftime('%Y-%m-%d %H:%M:%S'),
            "Cookies": attributes.get("cookies", []),
            "DOM Info": {
                "Title": attributes.get("dom_info", {}).get("title", ""),
                "Meta": attributes.get("dom_info", {}).get("meta", []),
                "Trackers": attributes.get("dom_info", {}).get("trackers", []),
                "Links": attributes.get("dom_info", {}).get("links", [])
            },
            "JavaScript Variables": attributes.get("javascript_variables", []),
            "Metrics": {
                "Array Buffer Contents": attributes.get("metrics", {}).get("array_buffer_contents", 0),
                "Task Duration": attributes.get("metrics", {}).get("task_duration", 0.0),
                "Nodes": attributes.get("metrics", {}).get("nodes", 0),
                "Frames": attributes.get("metrics", {}).get("frames", 0),
                "Process Time": attributes.get("metrics", {}).get("process_time", 0.0),
                "Event Listeners": attributes.get("metrics", {}).get("event_listeners", 0),
                "Script Duration": attributes.get("metrics", {}).get("script_duration", 0.0)
            },
            "Stats": {
                "Number of Requests": attributes.get("stats", {}).get("num_requests", 0),
                "Number of Cookies": attributes.get("stats", {}).get("num_cookies", 0),
                "Requests Distinct Subdomains": attributes.get("stats", {}).get("requests_distinct_subdomains", 0),
                "Requests Total Size": attributes.get("stats", {}).get("requests_total_size", 0),
                "Requests Distinct Countries": attributes.get("stats", {}).get("requests_distinct_countries", 0),
                "HTTP Requests": attributes.get("stats", {}).get("http_requests", 0),
                "Requests Distinct Domains": attributes.get("stats", {}).get("requests_distinct_domains", 0),
                "IPv6 Addresses": attributes.get("stats", {}).get("ipv6_adresses", 0),
                "IPv4 Addresses": attributes.get("stats", {}).get("ipv4_adresses", 0),
                "HTTPS Requests": attributes.get("stats", {}).get("https_requests", 0)
            },
            "URL": attributes.get("url", ""),
            "User Agent": attributes.get("user_agent", "")
        }


    section_data.update(section_data)

    return section_data

def parse_args(args):
    url = None
    full_data = False
    url_file = None
    sections = []
    help = """usage: ./virustotal.py <url|id> [-h] [-f] --file=[FILE]

An API script to gather data from https://www.virustotal.com/

optional arguments:
  -h, --help          Show this help message and exit.
  -f                  Retrieve the API full data.
  --file=[FILE]       Full path to a file containing URLs or IDs on each line.
  -g                  Retrieve general data (default if no section is specified).
  -a                  Retrieve all sections of data.
  -b                  Retrieve behavioral data for the URL (requires URL ID)."""

    analysis_id = None
    section_map = {
        'g': "",
        'b': "behaviours"
    }

    for arg in args:
        if arg == "--help" or arg == "-h":
            print(help)
            sys.exit(0)
        elif is_valid_url(arg):
            url = arg
        elif re.match(r'^u-[0-9a-f]{64}-[0-9]{10}$', arg):
            analysis_id = arg
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
        else:
            print(f"Error: Unknown input {arg}")
            print(help)
            sys.exit(1)
    
    return url, full_data, url_file, analysis_id, sections

def fetch_data(target, section):
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
        if section == "behaviours":
            analysis_id = analysis_id.replace("u-", "", 1)
            response = requests.get(f"{base_url}/urls/{analysis_id}/{section}", headers=headers)
            response.raise_for_status()
            data = response.json()
            return data
        else:    
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
    url, full_data, url_file, analysis_id, sections = parse_args(sys.argv[1:])
    sections = sections or [""]

    if not url and not url_file and not analysis_id:
        url = input("Enter your URL here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if url_file:
        with open(url_file, 'r') as file:
            urls = [line.strip() for line in file if is_valid_url(line.strip()) or re.match(r'^u-[0-9a-f]{64}-[0-9]{10}$', line.strip())]
    else:
        urls = [url]

    for url in urls:
        for section in sections:
            data = fetch_data(url or analysis_id, section)
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
