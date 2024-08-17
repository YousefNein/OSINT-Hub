#!/bin/python3

import requests
import sys
import json
import re
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

api_key = os.environ.get("SPAMHAUS_API_KEY")

headers = { 
    'Authorization':'Bearer ' + api_key 
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

    formatted_data = {}

    if section == "":
        formatted_data["General"] = {
            "Domain": data.get("domain"),
            "Last Seen": datetime.fromtimestamp(data.get("last-seen")).strftime('%Y-%m-%d'),
            "Tags": data.get("tags", []),
            "Abused": data.get("abused", False),
            "WHOIS": {
                "Created": datetime.fromtimestamp(data["whois"]["created"]).strftime('%Y-%m-%d') if data["whois"].get("created") else None,
                "Registrar": data["whois"].get("registrar")
            },
            "Score": data.get("score")
        }
    
    elif section == "/senders":
        formatted_data["Senders/MX Records"] = [
            {
                "IP": item.get("ip"),
                "HELO": item.get("helo"),
                "Last Seen": datetime.fromtimestamp(item.get("last-seen")).strftime('%Y-%m-%d'),
                "Score": item.get("score")
            } for item in data
        ]
    
    elif section == "/a":
        formatted_data["A Records"] = [
            {
                "IP": item.get("ip"),
                "Last Seen": datetime.fromtimestamp(item.get("last-seen")).strftime('%Y-%m-%d'),
                "Score": item.get("score"),
                "Counter": item.get("counter")
            } for item in data
        ]

    elif section == "/ns":
        formatted_data["NS Records"] = [
            {
                "NS": item.get("ns"),
                "Last Seen": datetime.fromtimestamp(item.get("last-seen")).strftime('%Y-%m-%d'),
                "Score": item.get("score"),
                "Counter": item.get("counter")
            } for item in data
        ]
    
    elif section == "/hostnames":
        formatted_data["Hostnames"] = [
            {
                "Hostname": item.get("hostname"),
                "Is Listed": item.get("is-listed"),
                "Abused": item.get("abused")
            } for item in data
        ]
    
    elif section == "/malware/urls":
        formatted_data["Malware URLs"] = [
            {
                "URL": item.get("url"),
                "Botname": item.get("botname"),
            } for item in data
        ]
    
    elif section == "/malware/hashes":
        formatted_data["Malware Hashes"] = [
            {
                "Type": item.get("type"),
                "Hash": item.get("hash"),
                "Botname": item.get("botname"),
            } for item in data
        ]
    
    return formatted_data


def parse_args(args):
    domain = None
    full_data = False
    domain_file = None
    sections = []
    help = """
usage: ./spamhaus.py <domain> [-h] [-f] [-a] [-g] [-s] [-i] [-n] [-o] [-u] [-m] --file==[FILE]

An API script to gather data from https://spamhaus.org/

optional arguments:
-h, --help     Show this help message and exit.
-f             Retrieve the API full data.
-a             Retrieve all sections data.
-g             Retrieve general domain data, including WHOIS information, tags, and score.
-s             Retrieve sender/MX records data, showing IP addresses and HELO information.
-i             Retrieve A records data, including IP addresses and their last seen timestamp.
-n             Retrieve NS records data, displaying nameservers and their last seen timestamp.
-o             Retrieve hostname data, including hostnames, timestamps, and abuse status.
-u             Retrieve malware URLs data, showing malicious URLs associated with the domain.
-m             Retrieve malware hashes data, listing hashes linked to the domain.
--file==[FILE] Full path to a test file containing a domain name on each line.
        """
    section_map = {
        'g': "",
        's': "/senders",
        'i': "/a",
        'n': "/ns",
        'o': "/hostnames",
        'u': "/malware/urls",
        'm': "/malware/hashes"
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
        response = requests.get(f"https://api.spamhaus.org/api/intel/v2/byobject/domain/{domain}{section}", headers=headers)
        response.raise_for_status()
        data = response.json()
        return data

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        print(response.json())

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
