#!/bin/python3

import requests
import sys
import json
import re
from dotenv import load_dotenv

load_dotenv()

headers = {
    'Accept': 'application/json'
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

    tags = set()
    target = set()
    pulses = data.get("pulse_info", {}).get("pulses", [])

    for pulse in pulses:
        tags.update(pulse.get("tags", []))
        target.update(pulse.get("targeted_countries", []))

    section_data = {}

    if section == "general":
        section_data["General"] = {
        "Domain": domain,
        "Country": data.get("country_name"),
        "AS Name": data.get("asn"),
        "Reputation": data.get("reputation"),
        "Related Pulses": data.get("pulse_info", {}).get("count", 0),
        "Tags Count": len(tags),
        "Related Tags": list(tags),
        "Targeted Countries": list(target)
    }
    elif section == "malware":
        section_data["Malware"] = {
            "Domain": domain,
            "Data": data.get("data", []),
            "Count": data.get("count", 0),
            "Size": data.get("size", 0),
        }

    elif section == "whois":
        section_data["Whois"] = {
            "Domain": domain,
            "Data": [
            f"{entry.get('name')}: {entry.get('value')}"
            for entry in data.get("data", [])
        ],
            "Related": [
        {
             "Domain" : entry.get("domain"),
             entry.get("related_type").title(): entry.get("related")
        }
            for entry in data.get("related", []) ],
            "Count": data.get("count")
        }

    elif section == "passive_dns":
        section_data["DNS"] = {
            "Domain": domain,
            "Passive DNS": [
        {        
                "IP Address": entry.get("address"),
                "Hostname": entry.get("hostname"),
                "Record Type": entry.get("record_type"),
                "AS Name": entry.get("asn"),
         
         }
            for entry in data.get("passive_dns", []) ],
            "Count": data.get("count", 0),
        }

    elif section == "geo":
        section_data["Geo"] = {
            "Domain": domain,
            "ASN": data.get("asn"),
            "Country": data.get("country_name"),
            "City": data.get("city"),
            "Region": data.get("region"),
            "Latitude": data.get("latitude"),
            "Longitude": data.get("longitude"),
        }

    elif section == "url_list":
        section_data["URL List"] = {
            "Domain": domain,
            "URL List": [
            {
                "URL": entry.get("url"),
                "Domain": entry.get("domain"),
                "Hostname": entry.get("hostname"),
                "Date": entry.get("date")
            }
            for entry in data.get("url_list", []) ],
            "Count": data.get("count", 0),
        }

    elif section == "http_scans":
        section_data["HTTP Scans"] = {
            "Domain": domain,
            "Data": [
                f"{entry.get('name')} : {entry.get('value')}"
                for entry in data.get("data", [])
            ],
            "Count": data.get("count", 0),
        }

    section_data.update(section_data)

    return section_data

def parse_args(args):
    domain = None
    full_data = False
    domain_file = None
    sections = []
    help = "usage: ./alienvault.py <domain> [-h] [-f] [-a] [-g] [-c] [-w] [-d] [-m] [-u] [-s] --file==[FILE]\n\nAn API script to gather data from https://otx.alienvault.com/\n\noptional arguments:\n  -h, --help     Show this help message and exit.\n  -f,             Retrieve the API full data.\n  -a              Retrieve all data.\n  -g              Retrieve general data.\n  -w              Retrieve WHOIS data.\n  -c              Retrieve Geo data.\n  -m              Retrieve Malware data.\n  -d              Retrieve Passive DNS data.\n  -u              Retrieve URL list data.\n  -s              Retrieve HTTP scans data.\n  --file==[FILE]  Full path to a test file containing a domain name on each line."
    
    section_map = {
        'g': "general",
        'c': "geo",
        'w': "whois",
        'm': "malware",
        'd': "passive_dns",
        'u': "url_list",
        's': "http_scans"
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
        elif re.search(r'(\.[a-zA-Z0-9-_]+))', arg):
            print(f"{arg} is not a valid domain name")
            sys.exit(1)
        else:
            print(f"Error: Unknown flag {arg}\n")
            print(help)
            sys.exit(1)
    
    return domain, full_data, domain_file, sections

try:
    domain, full_data, domain_file, sections = parse_args(sys.argv[1:])
    sections = sections or ["general"]

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
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/{section}"

            response = requests.get(url, headers=headers)
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
except Exception as e:
    print(f"An unexpected error occurred: {e}")
