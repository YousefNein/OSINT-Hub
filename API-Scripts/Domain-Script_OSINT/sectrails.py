#!/bin/python3

import requests
import os
import sys
import json
import re
from dotenv import load_dotenv

load_dotenv()

headers = {
    'Accept':'application/json',
    'APIKEY': os.environ.get('SECURITY_TRAILS')
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

    section_data = {}

    if section == "":
        section_data["Details"] = {
            "Domain": domain,
            "Hostname": data.get("hostname"),
            "A Records": [
                {"IP": record.get("ip"), "Organization": record.get("ip_organization")}
                for record in data.get("current_dns", {}).get("a", {}).get("values", [])
            ],
            "AAAA Records": [
                {"IPv6": record.get("ipv6"), "Organization": record.get("ipv6_organization")}
                for record in data.get("current_dns", {}).get("aaaa", {}).get("values", [])
            ],
            "MX Records": [
                {"Hostname": record.get("hostname"), "Organization": record.get("hostname_organization")}
                for record in data.get("current_dns", {}).get("mx", {}).get("values", [])
            ],
            "NS Records": [
                {"Nameserver": record.get("nameserver"), "Organization": record.get("nameserver_organization")}
                for record in data.get("current_dns", {}).get("ns", {}).get("values", [])
            ],
            "SOA Records": [
                {"Email": record.get("email")}
                for record in data.get("current_dns", {}).get("soa", {}).get("values", [])
            ]
        }

    elif section == "subdomains":
        section_data["Subdomain"] = {
            "Domain": domain,
            "Subdomains": data.get("subdomains", []),
            "Count": data.get("subdomain_count", 0)
        }
        
    section_data.update(section_data)

    return section_data

def parse_args(args):
    domain = None
    full_data = False
    domain_file = None
    sections = []
    help = "usage: ./sectrails.py <domain> [-h] [-f] [-a] [-s] [-d] --file=[FILE]\n\nAn API script to gather data from https://securitytrails.com/\n\noptional arguments:\n  -h,  --help    Show this help message and exit.\n  -f             Retrieve the full API data.\n  -a,            Retrieve data for all sections.\n  -s,            Retrieve subdomain data.\n  -d,            Retrieve DNS and domain data.\n  --file=[FILE]  Full path to a test file containing a domain name on each line."

    section_map = {
        'd' : '',
        's' : 'subdomains'
    }

    for arg in args:
        if arg == "--help" or arg == "-h":
            print(help)
            sys.exit(0)
        elif is_valid_domain(arg):
            domain = arg
        elif arg.startswith("--file="):
            domain_file = arg.split("=", 1)[1]
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
    
    return domain, full_data, domain_file, sections

try:
    domain, full_data, domain_file, sections = parse_args(sys.argv[1:])
    sections = sections or [""]

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
    
        for section in sections:
            url = f"https://api.securitytrails.com/v1/domain/{domain}/{section}"

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
