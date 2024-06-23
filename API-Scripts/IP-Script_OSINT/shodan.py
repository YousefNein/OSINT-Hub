#!/bin/python3

import requests
import os
import sys
import json
import re
from dotenv import load_dotenv

load_dotenv()

headers = {
    'Accept': 'application/json',
    'Authorization': os.environ.get("SHODAN")
}

def is_valid_ipv4(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if pattern.match(ip):
        return all(0 <= int(part) < 256 for part in ip.split('.'))
    return False

def filter_data(data):
    if data is None:
        return None

    filtered_data = {
        "ISP": data.get("isp"),
        "Hostname": data.get("hostnames"),
        "Domains": data.get("domains"),
        "Country": data.get("country_name"),
        "City": data.get("city"),
        "OS": data.get("os"),
        "IP": data.get("ip_str"),
        "Ports": data.get("ports"),
        "HTTP Status": data["data"][2]["http"]["status"]
    }
    return filtered_data

try:
    if len(sys.argv) > 1:
        ip = sys.argv[1]
    else:
        ip = input("Enter your IP address here:\n")

    if not is_valid_ipv4(ip):
        print(f"{ip} is not a valid IPv4 address")
        sys.exit(1)
        
    url = f"https://api.shodan.io/shodan/host/{ip}"

    response = requests.get(headers=headers, url=url)
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
