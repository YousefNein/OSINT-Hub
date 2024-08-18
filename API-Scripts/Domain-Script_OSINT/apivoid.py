#!/bin/python3

import requests
import os
import sys
import json
import re
from dotenv import load_dotenv

load_dotenv()

apivoid_key = os.getenv('API_VOID')

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

    report = data.get('data', {}).get('report', {})

    filtered_data = {
        "Domain": domain,
        "IP": report.get('server', {}).get('ip'),
        "ISP": report.get('server', {}).get('isp'),
        "Hostname": report.get('server', {}).get('reverse_dns'),
        "Country": report.get('server', {}).get('country_name'),
        "City": report.get('server', {}).get('city_name'),
        "Risk Score": report.get('risk_score', {}).get('result'),
        "Blacklist Detections": report.get('blacklists', {}).get('detections'),
        "Blacklist Engines Count": report.get('blacklists', {}).get('engines_count'),
        "Blacklist Detection Rate": report.get('blacklists', {}).get('detection_rate'),
    }

    boolean_fields = {
        "Is Free Hosting": report.get('category', {}).get('is_free_hosting'),
        "Is Anonymizer": report.get('category', {}).get('is_anonymizer'),
        "Is URL Shortener": report.get('category', {}).get('is_url_shortener'),
        "Is Free Dynamic DNS": report.get('category', {}).get('is_free_dynamic_dns'),
        "Is Code Sandbox": report.get('category', {}).get('is_code_sandbox'),
        "Is Form Builder": report.get('category', {}).get('is_form_builder'),
        "Is Free File Sharing": report.get('category', {}).get('is_free_file_sharing'),
        "Is Pastebin": report.get('category', {}).get('is_pastebin')
    }

    for field, value in boolean_fields.items():
        if value:
            filtered_data[field] = True

    return filtered_data

def parse_args(args):
    domain = None
    full_data = False
    domain_file = None
    help = "usage: ./apivoid.py <domain> [-h] [-f] --file==[FILE]\n\nAn API script to gather data from https://www.apivoid.com/\n\noptional arguments:\n  -h, --help      Show this help message and exit.\n  -f              Retrieve the API full data.\n  --file==[FILE]  Full path to a test file containing an IP address on each line."

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
        if not is_valid_domain(domain):
            print(f"{domain} is not a valid domain name")
            continue
    
        url = f"https://endpoint.apivoid.com/domainbl/v1/pay-as-you-go/?key={apivoid_key}&host={domain}"
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
