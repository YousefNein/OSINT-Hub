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

def filter_data(data, rt):
    if data is None or 'results' not in data:
        return None

    if data["status_message"] == "No results found.":
        return f"No data was found for IP {ip}"

    if rt == "rt=1":
        filtered_data = {
            "IP": ip,
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
                "IP": ip,
                "Domain": entry.get("domain"),
                "First Seen": entry.get("first_seen"),
                "Last Seen": entry.get("last_seen")
            }
            for entry in data["results"]
        ]
    elif rt == "rt=3":
        filtered_data = [
            {
                "IP": ip,
                "Domain": entry.get("domain"),
                "IP": entry.get("ip"),
                "URI": entry.get("uri"),
                "Last Seen": entry.get("last_seen")
            }
            for entry in data["results"]
        ]
    elif rt == "rt=4":
        filtered_data = { "IP": ip, "Hashes": data["results"]}
    elif rt == "rt=5":
        filtered_data = { "IP": ip, "Certificate": data["results"]}
    elif rt == "rt=6":
        filtered_data = [
            {
                "IP": ip,
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
    ip = None
    rt = None
    full_data = False
    ip_file = None
    help = "usage: ./threatminer.py <ip> [-h] [-f] --file==[FILE]  rt=[1 to 6]\n\nAn API script to gather data from https://www.threatminer.org/\n\noptional arguments:\n  -h, --help     Show this help message and exit.\n  -f,             Retrieve the API full data.\n  --file==[FILE]  Full path to a test file containing an IP address on each line.\n  rt=[1 to 6]        Specify the number of ThreatMiner flags.\n  rt=1 for WHOIS, rt=2 for Passive DNS, rt=3 for URIs, rt=4 for Related Samples, rt=5 for SSL Certificates, rt=6 for Report tagging"

    for arg in args:
        if arg == "--help" or arg == "-h":
            print(help)
            sys.exit(0)
        elif is_valid_ipv4(arg):
            ip = arg
        elif arg.startswith('rt='):
            rt = arg
        elif arg == '-f':
            full_data = True
        elif arg.startswith("--file="):
            ip_file = arg.split("=", 1)[1]
        else:
            print(f"Error: Unknown flag {arg}\n")
            print(help)
            sys.exit(1)
    
    return ip, rt, full_data, ip_file

try:
    ip, rt, full_data, ip_file = parse_args(sys.argv[1:])

    if not rt:
        rt = input("Enter the query type (rt=1 for WHOIS, rt=2 for Passive DNS, rt=3 for URIs, rt=4 for Related Samples, rt=5 for SSL Certificates, rt=6 for Report tagging):\n")
        if not rt.startswith('rt='):
            print(f"Error: Invalid query type {rt}")
            sys.exit(1)

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

        url = f"https://api.threatminer.org/v2/host.php?q={ip}&{rt}"

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
