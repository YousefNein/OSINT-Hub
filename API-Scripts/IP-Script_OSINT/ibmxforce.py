#!/bin/python3

import requests
import os
import sys
import json
import re
from dotenv import load_dotenv

load_dotenv()

headers_xf = {
    'accept': 'application/json',
    'Authorization': "Basic NDFlNjA4MmMtZjMyMi00NjhiLWI2NjItYzgzMTg1YjNiYTJhOmQ4Y2JkNjg4LWJhYWItNDRiYi05ZTUxLTRkNTJkOWEzNjlkMQ=="
}

def format_data(data):
    formatted_data = json.dumps(data, indent=4, sort_keys=False)
    return formatted_data

def is_valid_ipv4(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if pattern.match(ip):
        return all(0 <= int(part) < 256 for part in ip.split('.'))
    return False

def filter_data(data):
    if data is None:
        return None

    attributes = data.get("data", {})
    json_data_xf = response.json()
    max_score_ip = max(json_data_xf["history"], key=lambda x: x.get('score', 0))
    geolocation = json_data_xf.get("geo")
    categories = json_data_xf.get("cats")
    category_descriptions = json_data_xf.get("categoryDescriptions")
    if not categories or not category_descriptions:    
        categories = max_score_ip["cats"]
    category_descriptions = max_score_ip["categoryDescriptions"]
    reason_description = max_score_ip["reasonDescription"]
    score = max_score_ip["score"]
    filtered_data = {
        "geolocation": geolocation,
        "categories": categories,
        "categoryDescriptions": category_descriptions,
        "reasonDescription": reason_description,
        "score": score,
        "fullData_xf": json_data_xf
    }
    return filtered_data

def parse_args(args):
    ip = None
    full_data = False

    for arg in args:
        if is_valid_ipv4(arg):
            ip = arg
        elif arg == '-f':
            full_data = True
        else:
            print(f"Error: Unknown flag {arg}")
            sys.exit(1)
    
    return ip, full_data

try:
    ip, full_data = parse_args(sys.argv[1:])

    if not ip:
        ip = input("Enter your IP address here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if not is_valid_ipv4(ip):
        print(f"{ip} is not a valid IPv4 address")
        sys.exit(1)

    url_xf = f'https://api.xforce.ibmcloud.com/api/ipr/{ip}'
    response = requests.get(url_xf, headers=headers_xf)
    
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