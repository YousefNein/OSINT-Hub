#!/bin/python3

import requests
import sys
import json
import re
import time

def format_data(data):
    formatted_data = json.dumps(data, indent=4, sort_keys=False)
    return formatted_data

def is_valid_domain(domain):
    pattern = re.compile(r"^(?!:\/\/)([a-zA-Z0-9-_]+(\.[a-zA-Z0-9-_]+)+.*)$")
    if pattern.match(domain):
        return True
    return False

def filter_data(data, rt):
    if data is None or 'results' not in data:
        return None

    if data["status_message"] == "No results found.":
        return f"No data was found for IP {domain}"

    if rt == "rt=1":
        filtered_data = {
            "IP": domain,
            "Hostname": data["results"][0].get("reverse_name"),
            "Network": data["results"][0].get("bgp_prefix"),
            "Country": data["results"][0].get("cc"),
            "ASN": data["results"][0].get("asn"),
            "ASN Name": data["results"][0].get("asn_name"),
            "Organization": data["results"][0].get("org_name"),
            "Registrar": data["results"][0].get("register")
        }
    elif rt == "rt=2":
        filtered_data = [
            {
                "IP": domain,
                "Domain": entry.get("domain"),
                "First Seen": entry.get("first_seen"),
                "Last Seen": entry.get("last_seen")
            }
            for entry in data["results"]
        ]
    elif rt == "rt=3":
        filtered_data = [
            {
                "IP": domain,
                "Domain": entry.get("domain"),
                "IP": entry.get("domain"),
                "URI": entry.get("uri"),
                "Last Seen": entry.get("last_seen")
            }
            for entry in data["results"]
        ]
    elif rt == "rt=4":
        filtered_data = { "IP": domain, "Hashes": data["results"]}
    elif rt == "rt=5":
        filtered_data = { "IP": domain, "Certificate": data["results"]}
    elif rt == "rt=6":
        filtered_data = [
            {
                "IP": domain,
                "Filename": entry.get("filename"),
                "Year": entry.get("year"),
                "URL": entry.get("URL")
            }
            for entry in data["results"]
        ]
    else:
        filtered_data = data

    return filtered_data

def parse_args(args):
    domain = None
    rt = None
    full_data = False
    domain_file = None
    help = "usage: ./threatminer.py <domain> [-h] [-f] --file==[FILE]  rt=[1 to 6]\n\nAn API script to gather data from https://www.threatminer.org/\n\noptional arguments:\n  -h, --help     Show this help message and exit.\n  -f,             Retrieve the API full data.\n  --file==[FILE]    Full path to a test file containing a domain name on each line.\n  rt=[1 to 6]        Specify the number of ThreatMiner flags.\n  rt=1 for WHOIS, rt=2 for Passive DNS, rt=3 for URIs, rt=4 for Related Samples, rt=5 for SSL Certificates, rt=6 for Report tagging"

    for arg in args:
        if arg == "--help" or arg == "-h":
            print(help)
            sys.exit(0)
        elif is_valid_domain(arg):
            domain = arg
        elif arg.startswith('rt='):
            rt = arg
        elif arg == '-f':
            full_data = True
        elif arg.startswith("--file="):
            domain_file = arg.split("=", 1)[1]
        else:
            print(f"Error: Unknown flag {arg}\n")
            print(help)
            sys.exit(1)
    
    return domain, rt, full_data, domain_file

try:
    domain, rt, full_data, domain_file = parse_args(sys.argv[1:])

    if not rt:
        rt = input("Enter the query type (rt=1 for WHOIS, rt=2 for Passive DNS, rt=3 for URIs, rt=4 for Related Samples, rt=5 for SSL Certificates, rt=6 for Report tagging):\n")
        if not rt.startswith('rt='):
            print(f"Error: Invalid query type {rt}")
            sys.exit(1)

    if not domain and not domain_file:
        domain = input("Enter your domain name here:\n")

        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if domain_file:
        with open(domain_file, 'r') as file:
            domains = [line.strip() for line in file if is_valid_domain(line.strip())]
    else:
        domains = [domain]
    
    for domain in domains:
        time.sleep(6)
        if not is_valid_domain(domain):
            print(f"{domain} is not a valid domain name")
            continue

        url = f"https://api.threatminer.org/v2/host.php?q={domain}&{rt}"

        response = requests.get(url=url)

        response.raise_for_status()
        parsed = json.loads(response.text)

        if full_data:
            print(format_data(parsed))
        else:
            filtered_response = filter_data(parsed, rt)
            print(format_data(filtered_response))

except KeyboardInterrupt:
    print("\nProcess interrupted by user.")
except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
    print(response.json())
except Exception as e:
    print(f"An unexpected error occurred: {e}")
