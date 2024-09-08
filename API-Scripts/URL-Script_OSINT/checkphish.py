#!/bin/python3

import requests
import os
import sys
import json
import re
from dotenv import load_dotenv
from time import sleep

load_dotenv()

api_key = os.environ.get("CHECKPHISH_API_KEY")

headers = {
    'Content-Type': 'application/json'
}

base_url = "https://developers.checkphish.ai/api"

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

    if section == "quick":
        section_data["Quick Scan"] = {
            "URL": data.get("url"),
            "Job ID": data.get("job_id"),
            "URL SHA256": data.get("url_sha256"),
            "Disposition": data.get("disposition"),
            "Brand": data.get("brand"),
            "Insights": data.get("insights"),
            "Resolved": data.get("resolved"),
            "Error": data.get("error"),
            "Image Objects": data.get("image_objects") if isinstance(data.get("image_objects"), list) else [],
            "Categories": data.get("categories") if isinstance(data.get("categories"), list) else [],
            "Screenshot": data.get("screenshot_path")
        }

    elif section == "full":
        section_data["Full Scan"] = {
            "URL": data.get("url"),
            "Job ID": data.get("job_id"),
            "URL SHA256": data.get("url_sha256"),
            "Disposition": data.get("disposition"),
            "Brand": data.get("brand"),
            "Insights": data.get("insights"),
            "Resolved": data.get("resolved"),
            "Error": data.get("error"),
            "Image Objects": data.get("image_objects") if isinstance(data.get("image_objects"), list) else [],
            "Categories": data.get("categories") if isinstance(data.get("categories"), list) else [],
            "Screenshot": data.get("screenshot_path")
        }

    section_data.update(section_data)

    return section_data

def parse_args(args):
    url = None
    full_data = False
    url_file = None
    help = "usage: ./checkphish.py <url|jobid> [-h] [-f] --file=[FILE]\n\nAn API script to gather data from https://app.checkphish.ai/\n\noptional arguments:\n  -h, --help      Show this help message and exit.\n  -f              Retrieve the API full data.\n  -a              Retrieve all sections data.\n  -q              Retrieve quick scan data. (Default)\n  -u              Retrieve full scan data.\n  --file=[FILE]   Full path to a test file containing an URL on each line."
    jobid = None
    sections = []
    section_map = {
        'q': 'quick',
        'u': "full"
    }

    for arg in args:
        if arg == "--help" or arg == "-h":
            print(help)
            sys.exit(0)
        elif is_valid_url(arg):
            url = arg
        elif re.match(r'^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$', arg):
            jobid = arg
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
    
    return url, full_data, url_file, jobid, sections

class APIError(Exception):
    pass

def fetch_data(target, section):
    try:
        if is_valid_url(target):
            payload = {"apiKey": api_key, "urlInfo": {"url": target}, "scanType": section}
            response = requests.post(f"{base_url}/neo/scan", headers=headers, json=payload)
            response.raise_for_status()
            response = response.json()

            if "errorMessage" in response:
                raise APIError(f"Error in response: {response['errorMessage']}")

            jobid = response.get("jobID")
            if not jobid:
                raise APIError("Job ID is missing")

            print(f"Analysing the URL with this ID {jobid}...\n")
        else:
            jobid = target

        while True:
            payload = {"apiKey": api_key, "jobID": jobid, "insights": "true"}
            response = requests.post(f"{base_url}/neo/scan/status", headers=headers, json=payload)
            data = response.json()

            if "errorMessage" in data:
                raise APIError(f"Error in response: {data['errorMessage']}")

            if data.get("status") != "DONE":
                sleep(5)
            elif data.get("status") == "DONE":
                return data
    except requests.exceptions.RequestException as e:
        print(f"An error occurred during the request: {e}")
    except APIError as e:
        print(f"API error: {e}")

try:
    url, full_data, url_file, jobid, sections = parse_args(sys.argv[1:])
    sections = sections or ["quick"]

    if not url and not url_file and not jobid:
        url = input("Enter your URL here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if url_file:
        with open(url_file, 'r') as file:
            urls = [line.strip() for line in file if is_valid_url(line.strip()) or re.match(r'^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$', line.strip())]
    else:
        urls = [url]

    for url in urls:
        for section in sections:
            data = fetch_data(url or jobid, section)
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
