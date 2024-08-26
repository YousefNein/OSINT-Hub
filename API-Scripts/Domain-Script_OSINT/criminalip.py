#!/bin/python3

import requests
import sys
import json
import re
import os
from dotenv import load_dotenv

load_dotenv()

headers = {
    'Accept': 'application/json',
    'x-api-key': os.environ.get('CRIMINAL_IP_API')
}

def format_data(data):
    formatted_data = json.dumps(data, indent=4, sort_keys=False)
    return formatted_data

def is_valid_domain(domain):
    pattern = re.compile(r"^(?!:\/\/)([a-zA-Z0-9-_]+(\.[a-zA-Z0-9-_]+)+.*)$")
    if pattern.match(domain):
        return True
    return False

def filter_data(data):
    if data is None:
        return None

    data = data.get("data", {})
    filtered_data = {
        "Reports Count": data.get("count", 0),
        "Reports": [
            {
                "Connected IP Count": report.get("connected_ip_cnt", 0),
                "Country": report.get("country_code", []),
                "Issue": report.get("issue", []),
                "Registration Date": report.get("reg_dtime", {}),
                "Scan ID": report.get("scan_id", {}),
                "Score": report.get("score", {}),
                "Technologies": [
                    tech.get("tech_name", "No tech name")
                    for tech in report.get("technologies", [])
                ],
                "Title": report.get("title", "No title"),
                "URL": report.get("url", []),
            }
            for report in data.get("reports", [])
        ]
    }
    
    return filtered_data
    

def parse_args(args):
    domain = None
    full_data = False
    domain_file = None
    help = "usage: ./criminalip.py <domain> [-h] [-f] --file==[FILE]\n\nAn API script to gather data from https://criminalip.io/\n\noptional arguments:\n  -h, --help     Show this help message and exit.\n  -f              Retrieve the API full data.\n  --file==[FILE]  Full path to a test file containing a domain name on each line."

    for arg in args:
        if arg == "--help" or arg == "-h":
            print(help)
            sys.exit(0)
        elif is_valid_domain(arg):
            domain = arg
        elif arg == '-f':
            full_data = True
        elif arg.startswith("--file="):
            domain_file = arg.split("=", 1)[1]
        elif arg.startswith('-'):
            print(f"Error: Unknown flag {arg}")
            print(help)
            sys.exit(1)
        else:
            print(f"Error: Unknown input {arg}")
            print(help)
            sys.exit(1)
    
    return domain, full_data, domain_file

def fetch_data(domain):
    try:
        response = requests.get(f'https://api.criminalip.io/v1/domain/reports?query={domain}&offset=0', headers=headers)
        response.raise_for_status()
        data = response.json()
        return data

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        print(response.json())


try:
    domain, full_data, domain_file = parse_args(sys.argv[1:])

    if not domain and not domain_file:
        domain = input("Enter your domain name here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if domain_file:
        with open(domain_file, 'r') as file:
            domains = [line.strip() for line in file if is_valid_domain(line.strip())]
    else:
        domains = [domain]

    for domain in domains:
        data = fetch_data(domain)
        if data is None:
            break
        elif full_data:
            print(format_data(data))
        else:
            filtered_response = filter_data(data)
            print(format_data(filtered_response))

except KeyboardInterrupt:
    print("\nProcess interrupted by user.")
except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
