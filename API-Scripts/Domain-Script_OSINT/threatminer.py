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

def filter_data(data, section, domain):
    if data is None or 'results' not in data:
        return None
    
    section_data = {}

    if section == "1":
        section_data["Whois"] = [
            {
            "Domain": domain,
            "Updated Date": entry.get("whois", {}).get("updated_date"),
            "Creation Date": entry.get("whois", {}).get("creation_date"),
            "Expiration Date": entry.get("whois", {}).get("expiration_date"),
            "Registrar": entry.get("whois", {}).get("registrar"),
            "Whois Server": entry.get("whois", {}).get("whois_server"),
            "Nameservers": entry.get("whois", {}).get("nameservers"),
            "Registrant Info": entry.get("whois", {}).get("registrant_info"),
            "Date Checked": entry.get("whois", {}).get("date_checked")
            }
            for entry in data["results"]
        ]
    elif section == "2":
        section_data["DNS"] = [
            {
                "Domain": domain,
                "IP": entry.get("ip"),
                "First Seen": entry.get("first_seen"),
                "Last Seen": entry.get("last_seen")
            }
            for entry in data["results"]
        ]
    elif section == "3":
        section_data["URI"] = [
            {
                "Domain": domain,
                "Domain": entry.get("domain"),
                "URI": entry.get("uri"),
                "Last Seen": entry.get("last_seen")
            }
            for entry in data["results"]
        ]
    elif section == "4":
        section_data["Hashes"] = { "Domain": domain, "Hashes": data["results"]}
    elif section == "5":
        section_data["Subdomains"] = { "Domain": domain, "Certificate": data["results"]}
    elif section == "6":
        section_data["Reports"] = [
            {
                "Domain": domain,
                "Filename": entry.get("filename"),
                "Year": entry.get("year"),
                "URL": entry.get("URL")
            }
            for entry in data["results"]
        ]
    else:
        section_data = data

    return section_data

def parse_args(args):
    domain = None
    full_data = False
    ip_file = None
    sections = []
    help = "usage: ./threatminer.py <domain> [-h] [-f] [-a] [-w] [-d] [-u] [-r] [-s] [-t] --file==[FILE]\n\nAn API script to gather data from https://www.threatminer.org/\n\noptional arguments:\n  -h, --help     Show this help message and exit.\n  -f             Retrieve the API full data.\n  -a             Retrieve all sections data.\n  -w             Retrieve WHOIS data.\n  -d             Retrieve Passive DNS data.\n  -u             Retrieve URIs.\n  -r             Retrieve Related Samples (Hash only).\n  -s             Retrieve Subdomains.\n  -t             Retrieve Report tagging data.\n  --file==[FILE] Full path to a test file containing a domain on each line."

    section_map = {
        'w': '1',
        'd': "2",
        'u': "3",
        'r': "4",
        's': "5",
        't': "6"
    }

    for arg in args:
        if arg == "--help" or arg == "-h":
            print(help)
            sys.exit(0)
        elif is_valid_domain(arg):
            domain = arg
        elif arg.startswith("--file="):
            ip_file = arg.split("=", 1)[1]
        elif arg.startswith('-'):
            for flag in arg[1:]:
                if flag == 'f':
                    full_data = True
                elif flag == 'a':
                    sections = list(section_map.values())
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
    
    return domain, full_data, ip_file, sections

try:
    domain, full_data, ip_file, sections = parse_args(sys.argv[1:])
    sections = sections or ["1"]

    if not domain and not ip_file:
        domain = input("Enter your domain here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if ip_file:
        with open(ip_file, 'r') as file:
            ips = [line.strip() for line in file if is_valid_domain(line.strip())]
    else:
        ips = [domain]
    
    for domain in ips:
        time.sleep(6)
        if not is_valid_domain(domain):
            print(f"{domain} is not a valid domain")
            continue

        for section in sections:
            url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt={section}"

            response = requests.get(url=url)
            response.raise_for_status()
            parsed = json.loads(response.text)

            if full_data:
                print(format_data(parsed))
            else:
                filtered_response = filter_data(parsed, section, domain)
                print(format_data(filtered_response))

except KeyboardInterrupt:
    print("\nProcess interrupted by user.")
except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
    print(response.json())
except Exception as e:
    print(f"An unexpected error occurred: {e}")
