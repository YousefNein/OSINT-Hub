#!/bin/python3

import requests
import sys
import json
import re
import time

def format_data(data):
    formatted_data = json.dumps(data, indent=4, sort_keys=False)
    return formatted_data

def is_valid_ipv4(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if pattern.match(ip):
        return all(0 <= int(part) < 256 for part in ip.split('.'))
    return False

def filter_data(data, section, ip):
    if data is None or 'results' not in data:
        return None
    
    section_data = {}

    if section == "1":
        section_data["Whois"] = [
            {
            "IP": ip,
            "Hostname": entry.get("reverse_name"),
            "Network": entry.get("bgp_prefix"),
            "Country": entry.get("cc"),
            "Org": entry.get("org_name"),
            "Register": entry.get("register")
            }
        for entry in data["results"]
        ]
    elif section == "2":
        section_data["DNS"] = [
            {
                "IP": ip,
                "Domain": entry.get("domain"),
                "First Seen": entry.get("first_seen"),
                "Last Seen": entry.get("last_seen")
            }
            for entry in data["results"]
        ]
    elif section == "3":
        section_data["URI"] = [
            {
                "IP": ip,
                "Domain": entry.get("domain"),
                "URI": entry.get("uri"),
                "Last Seen": entry.get("last_seen")
            }
            for entry in data["results"]
        ]
    elif section == "4":
        section_data["Hashes"] = { "IP": ip, "Hashes": data["results"]}
    elif section == "5":
        section_data["SSL Certificate"] = { "IP": ip, "Certificate": data["results"]}
    elif section == "6":
        section_data["Reports"] = [
            {
                "IP": ip,
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
    ip = None
    full_data = False
    ip_file = None
    sections = []
    help = "usage: ./threatminer.py <ip> [-h] [-f] [-a] [-w] [-d] [-u] [-r] [-s] [-t] --file==[FILE]\n\nAn API script to gather data from https://www.threatminer.org/\n\noptional arguments:\n  -h, --help     Show this help message and exit.\n  -f             Retrieve the API full data.\n  -a             Retrieve all data.\n  -w             Retrieve WHOIS data.\n  -d             Retrieve Passive DNS data.\n  -u             Retrieve URIs.\n  -r             Retrieve Related Samples (Hash only).\n  -s             Retrieve SSL Certificates (Hash only).\n  -t             Retrieve Report tagging data.\n  --file==[FILE] Full path to a test file containing an IP address on each line."

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
        elif is_valid_ipv4(arg):
            ip = arg
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
    
    return ip, full_data, ip_file, sections

try:
    ip, full_data, ip_file, sections = parse_args(sys.argv[1:])
    sections = sections or ["1"]

    if not ip and not ip_file:
        ip = input("Enter your IP address here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if ip_file:
        with open(ip_file, 'r') as file:
            ips = [line.strip() for line in file if is_valid_ipv4(line.strip())]
    else:
        ips = [ip]
    
    for ip in ips:
        time.sleep(6)
        if not is_valid_ipv4(ip):
            print(f"{ip} is not a valid IPv4 address")
            continue

        for section in sections:
            url = f"https://api.threatminer.org/v2/host.php?q={ip}&rt={section}"

            response = requests.get(url=url)
            response.raise_for_status()
            parsed = json.loads(response.text)

            if full_data:
                print(format_data(parsed))
            else:
                filtered_response = filter_data(parsed, section, ip)
                print(format_data(filtered_response))

except KeyboardInterrupt:
    print("\nProcess interrupted by user.")
except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
    print(response.json())
except Exception as e:
    print(f"An unexpected error occurred: {e}")
