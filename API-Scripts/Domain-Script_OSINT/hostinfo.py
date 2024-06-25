#!/bin/python3

import requests
import os
import sys
import json
import re
from dotenv import load_dotenv

token = "c1ed541fba0ac8"

load_dotenv()

# def is_valid_ipv4(ip):
#     pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
#     if pattern.match(ip):
#         return all(0 <= int(part) < 256 for part in ip.split('.'))
#     return False

def filter_data(data):
    if data is None:
        return None

    attributes = data.get("data", {})

    filtered_data = {
        "abuse_confidence_score": attributes.get('abuseConfidenceScore'),
        "country_code": attributes.get('countryCode'),
        "usage_type": attributes.get('usageType'),
        "isp": attributes.get('isp'),
        "domain": attributes.get('domain'),
        "total_reports": attributes.get('totalReports'),
        "last_reported_at": attributes.get('lastReportedAt')
    }
    return filtered_data

try:
    if len(sys.argv) > 1:
        ip = sys.argv[1]
    else:
        ip = input("Enter your IP address here:\n")

    # if not is_valid_ipv4(ip):
    #     print(f"{ip} is not a valid IPv4 address")
    #     sys.exit(1)
    
    url = f"https://host.io/api/full/google.com?token={token}"

    response = requests.get(url)

    response.raise_for_status()
    parsed = json.loads(response.text)

    ask = input("Do you want the full data to be shown? Y/n\n")
    if ask.lower() == "y" or ask == "": 
        print(json.dumps(parsed, indent=4, sort_keys=True))
    elif ask.lower() == "n":
        pass
    else:
        print("A wrong input. Choose Y or N")

    response = filter_data(response.json())
    print(response)
    
except KeyboardInterrupt:
    print("\nProcess interrupted by user.")
except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
