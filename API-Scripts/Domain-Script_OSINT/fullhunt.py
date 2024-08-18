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
    'X-API-KEY': os.environ.get("FULLHUNT_API_KEY")
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

    if section == "details":
        section_data["Domain"] = {
            "Domain": data.get("domain"),
            "hosts":[
                {
                "Host": host.get("host"),
                "IP Address": host.get("ip_address"),
                "DNS": host.get("dns"),
                "Country": host.get("ip_metadata", {}).get("country_name"),
                "ISP": host.get("ip_metadata", {}).get("isp"),
                "Network Ports": host.get("network_ports"),
                "Cloud ": host.get("cloud", {}),
                "CDN": host.get("cdn"),
                "HTTP Status Code": host.get("http_status_code"),
                "Tags": host.get("tags"),
                "URLs": data.get("urls"),
                    **{key: value for key, value in {
                        "Is CDN": host.get("is_cdn"),
                        "Is Cloud": host.get("is_cloud"),
                        "Is Cloudflare": host.get("is_cloudflare"),
                        "Is Live": host.get("is_live"),
                        "Is Resolvable": host.get("is_resolvable"),
                        "Has IPv6": host.get("has_ipv6"),
                        "Has Private IPs": host.get("has_private_ip")
                    }.items() if value}
            } for host in data.get("hosts", {})
            ]
    }
        
    elif section == "host":
        section_data["Host"] = {
                "Host": data.get("host"),
                "IP Address": data.get("ip_address"),
                "DNS": data.get("dns"),
                "Country": data.get("ip_metadata", {}).get("country_name"),
                "ISP": data.get("ip_metadata", {}).get("isp"),
                "Network Ports": data.get("network_ports"),
                "Cloud ": data.get("cloud", {}),
                "CDN": data.get("cdn"),
                "HTTP Status Code": data.get("http_status_code"),
                "Tags": data.get("tags"),
                "URLs": data.get("urls"),
                    **{key: value for key, value in {
                        "Is CDN": data.get("is_cdn"),
                        "Is Cloud": data.get("is_cloud"),
                        "Is Cloudflare": data.get("is_cloudflare"),
                        "Is Live": data.get("is_live"),
                        "Is Resolvable": data.get("is_resolvable"),
                        "Has IPv6": data.get("has_ipv6"),
                        "Has Private IPs": data.get("has_private_ip")
                    }.items() if value}
            }
        
    elif section == "subdomains":
        section_data["Subdomains"] = {
            "Domain": data.get("domain",{}),
            "hosts": data.get("hosts", []),
            "Message": data.get("message",{}),
    }

    return section_data

def parse_args(args):
    domain = None
    full_data = False
    domain_file = None
    sections = []
    help = "usage: ./fullhunt.py <domain> [-h] [-f] [-a] [-d] [-s] [-o] --file==[FILE]\n\nAn API script to gather data from https://otx.alienvault.com/\n\noptional arguments:\n  -h, --help     Show this help message and exit.\n  -f              Retrieve the API full data.\n  -a              Retrieve all sections data.\n  -d              Retrieve details about a domain (Default).\n  -s              Retrieve subdomains data.\n  -o              Retrieve hostnames data.\n  --file==[FILE]  Full path to a test file containing a domain name on each line."
    
    section_map = {
        'd': "details",
        's': "subdomains",
        'o': "host"
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
        elif arg.startswith('-'):
            print(f"Error: Unknown flag {arg}")
            print(help)
            sys.exit(1)
        else:
            print(f"Error: Unknown input {arg}")
            print(help)
            sys.exit(1)
    
    return domain, full_data, domain_file, sections

def fetch_data(domain, section):
    try:
        if section == "host":
            response = requests.get(f"https://fullhunt.io/api/v1/host/{domain}", headers=headers)
        else:
            response = requests.get(f"https://fullhunt.io/api/v1/domain/{domain}/{section}", headers=headers)
        response.raise_for_status()
        data = response.json()
        return data

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        print(response.json())

try:
    domain, full_data, domain_file, sections = parse_args(sys.argv[1:])
    sections = sections or ["details"]

    if not domain and not domain_file:
        domain = input("Enter your domain name here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if domain_file:
        with open(domain_file, 'r') as file:
            domains = [line.strip() for line in file if is_valid_domain(line.strip())]
    else:
        domains = [domain]

    for domain in domains:
        for section in sections:
            data = fetch_data(domain,section)
            if data is None:
                break
            elif full_data:
                print(format_data(data))
            else:
                filtered_response = filter_data(data)
                print(format_data(filtered_response))

except KeyboardInterrupt:
    print("\nProcess interrupted by user.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
