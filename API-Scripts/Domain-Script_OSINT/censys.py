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
    'Authorization': os.environ.get("CENSYS_API")
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
    
    filtered_data = {
        "Domain": domain,
        "Hits": [
            {
                "IP": entry.get("ip"),
                "Country": entry.get("location", {}).get("country"),
                "City": entry.get("location", {}).get("city"),
                "Last Updated": entry.get("last_updated_at"),
                "DNS": entry.get("reverse_dns", {}).get("names", []),
                "Autonomous System": {
                    "Description" : entry.get("autonomous_system", {}).get("description"),
                    "BGP Prefix" : entry.get("autonomous_system", {}).get("bgp_prefix")
                    },
                "OS": {
                    "Product" : entry.get("operating_system", {}).get("product"),
                    "Vendor" : entry.get("operating_system", {}).get("vendor")
                    },
                "Services":[
                    {
                    "Service Name": services.get('service_name'),
                    "Port": services.get('port')
                    }
                for services in entry.get("services", []) ],
            }
        for entry in data.get("result").get("hits", []) ],
    }

    return filtered_data

def parse_args(args):
    domain = None
    full_data = False
    domain_file = None
    help = "usage: ./censys.py <domain> [-h] [-f] --file==[FILE]\n\nAn API script to gather data from https://search.censys.io/\n\noptional arguments:\n  -h, --help       Show this help message and exit.\n  -f,              Retrieve the API full data.\n  --file==[FILE]   Full path to a test file containing a domain name on each line."

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

        url = f"https://search.censys.io/api/v2/hosts/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q={domain}"

        response = requests.get(headers=headers, url=url)
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
