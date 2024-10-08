#!/bin/python3

import requests
import os
import sys
import json
import re
import base64
from dotenv import load_dotenv

load_dotenv()

api_key = os.environ.get("IBM_XFORCE_API_KEY")
api_key_password = os.environ.get("IBM_XFORCE_API_PASS")
credentials = f"{api_key}:{api_key_password}"
encoded_credentials = base64.b64encode(credentials.encode()).decode()

headers = {
    'accept': 'application/json',
    'Authorization': f"Basic {encoded_credentials}"
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

    section_data = {}

    if section == "":
        max_score_ip = max(data["history"], key=lambda x: x.get('score', 0))
        categories = data.get("cats")
        category_descriptions = data.get("categoryDescriptions")
        if not categories or not category_descriptions:
            categories = max_score_ip["cats"]
        category_descriptions = max_score_ip["categoryDescriptions"]

        section_data["Report"] = {
            "IP": data.get("ip"),
            "Country": data.get("geo").get("country"),
            "Network": max_score_ip["ip"],
            "First seen": max_score_ip["created"],
            "Reports count": len(data.get("history", [])),
            "Score": data.get("score"),
            "Max score": max_score_ip["score"],
            "Categories": data.get("cats"),
            "Category Description": category_descriptions,
            "Reason": max_score_ip["reasonDescription"]
        }

    elif section == "/malware":
            section_data["Malware"] = {
                "IP": ip,
                "Data": [
                    {
                        "Type": entry.get("type"),
                        "MD5": entry.get("md5"),
                        "Host": entry.get("host"),
                        "FirstSeen": entry.get("firstseen"),
                        "Last Seen": entry.get("lastseen"),
                        "Count": entry.get("count"),
                        "Filepath": entry.get("filepath"),
                        "URI": entry.get("uri"),
                        "Origin": entry.get("origin"),
                        "Family": entry.get("family"),
                    }
                    for entry in data.get("malware", [])
                ],
            }

    section_data.update(section_data)

    return section_data

def parse_args(args):
    ip = None
    full_data = False
    ip_file = None
    sections = []
    help = "usage: ./ibmxforce.py <ip> [-h] [-f] --file==[FILE]\n\nAn API script to gather data from https://exchange.xforce.ibmcloud.com/\n\noptional arguments:\n  -h, --help      Show this help message and exit.\n  -f              Retrieve the API full data.\n  --file==[FILE]  Full path to a test file containing an IP address on each line."
    
    section_map = {
        'r': '', # report
        # 's': "/history",
        'm': "/malware"
    }

    for arg in args:
        if arg == "--help" or arg == "-h":
            print(help)
            sys.exit(0)
        elif is_valid_ipv4(arg):
            ip = arg
        elif arg.startswith("--file="):
            ip_file = arg.split("=", 1)[1]
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
        elif re.search(r'[0-9]{1,4}', arg):
            print(f"{arg} is not a valid IPv4 address")
            sys.exit(1)
        else:
            print(f"Error: Unknown input {arg}\n")
            print(help)
            sys.exit(1)
    
    return ip, full_data, ip_file, sections

try:
    ip, full_data, ip_file, sections = parse_args(sys.argv[1:])
    sections = sections or [""]

    if not ip and not ip_file:
        ip = input("Enter your IP address here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if ip_file:
        with open(ip_file, 'r') as file:
            ips = [line.strip() for line in file if is_valid_ipv4(line.strip())]
    else:
        ips = [ip]

    for ip in ips:
        if not is_valid_ipv4(ip):
            print(f"{ip} is not a valid IPv4 address")
            continue

        for section in sections:
            url = f'https://api.xforce.ibmcloud.com/api/ipr{section}/{ip}'
            response = requests.get(url=url, headers=headers)

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