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
    'x-api-key': os.environ.get('CRIMINAL_IP_API')
}

def format_data(data):
    formatted_data = json.dumps(data, indent=4, sort_keys=False)
    return formatted_data

def is_valid_ipv4(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if pattern.match(ip):
        return all(0 <= int(part) < 256 for part in ip.split('.'))
    return False

def filter_data(data):
    if data is None:
        return None

    section_data = {}

    if section == 'asset/ip/report':
        section_data["Report"] = {
            "IP": data.get("ip"),
            "Issues": data.get("issues"),
            "Score": data.get("score", {}),
            "Score": data.get("score"),
            "Domains": [
                {
                    "Domain": domain.get("domain"),
                    "Registrar": domain.get("registrar"),
                    "Email": domain.get("email"),
                    "Created Date": domain.get("created_date")
                } for domain in data.get("domain", {}).get("data", [])
            ],
            "Whois": [
                {
                    "AS Name": whois.get("as_name"),
                    "Organization": whois.get("org_name"),
                    "Organization Country": whois.get("org_country_code")
                } for whois in data.get("whois", {}).get("data", [])
            ],
            "Hostnames": [
                    hostname.get("domain_name_full") 
                    for hostname in data.get("hostname", {}).get("data", [])
                ],
            "IDS": [
                {
                    "URL": ids.get("url"),
                    "Message": ids.get("message"),
                    "Source System": ids.get("source_system"),
                } for ids in data.get("ids", {}).get("data", [])
            ],
            "VPN": [
                {
                    "VPN Name": vpn.get("vpn_name"),
                    "VPN Source": vpn.get("vpn_source_url")
                } for vpn in data.get("vpn", {}).get("data", [])
            ],
            "Anonymous VPN": [
                {
                    "VPN Name": anonymous.get("vpn_name"),
                    "VPN Source": anonymous.get("vpn_source_url")
                } for anonymous in data.get("anonymous_vpn", {}).get("data", [])
            ],
            "Webcams": [
            {
                "Image Path": webcam.get("image_path"),
                "Camera URL": webcam.get("cam_url"),
                "Country": webcam.get("country")
            } for webcam in data.get("webcam", {}).get("data", [])
        ],
            "Honeypot": [
            {
                "IP Address": honeypot.get("ip_address"),
                "Destination Port": honeypot.get("dst_port"),
                "Message": honeypot.get("message"),
                "User Agent": honeypot.get("user_agent")
            } for honeypot in data.get("honeypot", {}).get("data", [])
        ],   
            "IP Category": [
            {
                "Source": ip_category.get("detect_source"),
                "Type": ip_category.get("type"),
                "Info": ip_category.get("detect_info"),
            } for ip_category in data.get("ip_category", {}).get("data", [])
        ],     
            "Ports": [
            {
                "App Name": port.get("app_name"),
                "Banner": port.get("banner"),
                "App Version": port.get("app_version"),
                "Open Port Number": port.get("open_port_no"),
                "Port Status": port.get("port_status"),
                "Protocol": port.get("protocol"),
                "Tags": port.get("tags", []),
                "DNS Names": port.get("dns_names"),
                "SDN Common Name": port.get("sdn_common_name"),
                "JARM Hash": port.get("jarm_hash"),
                "Technologies": [
                    {
                        "Tech Name": tech.get("tech_name"),
                        "Tech Version": tech.get("tech_version"),
                        "Tech Logo URL": tech.get("tech_logo_url")
                    } for tech in port.get("technologies", [])
                ],
                "Is Vulnerability": port.get("is_vulnerability")
            } for port in data.get("port", {}).get("data", [])
        ],
            "Vulnerabilities": [
            {
                "CVE ID": vuln.get("cve_id"),
                "Description": vuln.get("cve_description"),
                "CVSSv3 Vector": vuln.get("cvssv3_vector"),
                "CVSSv3 Score": vuln.get("cvssv3_score"),
                "Application Name": vuln.get("app_name"),
                "Vendor": vuln.get("vendor"),
                "Type": vuln.get("type"),
                "Is Vulnerable": vuln.get("is_vuln")
            } for vuln in data.get("vulnerability", {}).get("data", [])
        ],
        }

    elif section == 'asset/ip/report/summary':
        section_data["Report Summary"] = {
            "IP": ip,
            "Issue": data.get("issue"),
            "Tags": data.get("tags", {}),
            "IP Scoring": {
            "Inbound": data.get("ip_scoring", {}).get("inbound", "Unknown"),
            "Outbound": data.get("ip_scoring", {}).get("outbound", "Unknown"),
            "Is Malicious": data.get("ip_scoring", {}).get("is_malicious", False)
            },
            "Current Open Ports": data.get("current_open_ports", {}),
            "Summary": {
            "Connection": {
                "Representative Domain": data.get("summary", {}).get("connection", {}).get("representative_domain"),
                "IP Address Owner": data.get("summary", {}).get("connection", {}).get("ip_address_owner", "Unknown"),
                "Hostname": data.get("summary", {}).get("connection", {}).get("hostname", "Unknown"),
                "Connected Domains": data.get("summary", {}).get("connection", {}).get("connected_domains", 0),
                "Country": data.get("summary", {}).get("connection", {}).get("country", "Unknown").upper()
            },
            "Detection": data.get("summary", {}).get("detection", {}),
            "Security": {
                "Abuse Record": data.get("summary", {}).get("security", {}).get("abuse_record", 0),
                "Open Ports": data.get("summary", {}).get("security", {}).get("open_ports", 0),
                "Vulnerabilities": data.get("summary", {}).get("security", {}).get("vulnerabilities", 0),
                "Exploit DB": data.get("summary", {}).get("security", {}).get("exploit_db", 0),
                "Policy Violation": data.get("summary", {}).get("security", {}).get("policy_violation", 0),
                "Remote Address": data.get("summary", {}).get("security", {}).get("remote_address", False),
                "Network Device": data.get("summary", {}).get("security", {}).get("network_device", False),
                "Admin Page": data.get("summary", {}).get("security", {}).get("admin_page", False),
                "Invalid SSL": data.get("summary", {}).get("security", {}).get("invalid_ssl", False)
            },
            "DNS Service": data.get("summary", {}).get("dns_service", {})
        },
        }

    elif section == 'asset/ip/summary':
        section_data["Summary"] = {
           "IP": data.get("ip"),
            "Score": data.get("score"),
            "Country": data.get("country"),
            "ISP": data.get("isp"),
            "Organization Name": data.get("org_name")
        }

    elif section == 'ip/vpn':
        section_data["VPN"] = {
        "IP": data.get("ip"),
        "VPN Info": {
            "VPN": [
                    {
                        "VPN Name": vpn.get("vpn_name"),
                        "VPN URL": vpn.get("vpn_url"),
                        "VPN Source URL": vpn.get("vpn_source_url"),
                        "Socket Type": vpn.get("socket_type"),
                        "Confirmed Time": vpn.get("confirmed_time")
                    }
                    for vpn in data.get("vpn_info", {}).get("vpn", {}).get("data", [])
                ],
            "Anonymous VPN": [
                    {
                        "VPN Name": vpn.get("vpn_name"),
                        "VPN URL": vpn.get("vpn_url"),
                        "VPN Source URL": vpn.get("vpn_source_url"),
                        "Socket Type": vpn.get("socket_type"),
                        "Confirmed Time": vpn.get("confirmed_time")
                    }
                    for vpn in data.get("vpn_info", {}).get("anonymous_vpn", {}).get("data", [])
                ],
            "IP Category": [
                    {
                        "Confirmed Time": category.get("confirmed_time"),
                        "Detect Reason": category.get("detect_reason"),
                        "Detect Source": category.get("detect_source"),
                        "Detect Type": category.get("detect_type"),
                        "Detect Count": category.get("detect_cnt", 0)
                    }
                    for category in data.get("vpn_info", {}).get("ip_category", {}).get("data", [])
                ],
            "Hostname": [
                    {
                        "Domain Name Representative": hostname.get("domain_name_rep"),
                        "Domain Name Full": hostname.get("domain_name_full"),
                        "Confirmed Time": hostname.get("confirmed_time")
                    }
                    for hostname in data.get("vpn_info", {}).get("hostname", {}).get("data", [])
                ],
        }}

    elif section == 'ip/malicious-info':
        section_data["Malicious Info"] = {
            "IP": data.get("ip"),
            "Is Malicious": data.get("is_malicious", False),
            "Is VPN": data.get("is_vpn", False),
            "Is Anonymous VPN": data.get("is_anonymous_vpn", False),
            "Can Remote Access": data.get("can_remote_access", False),
            "Current Open Ports": [
                    {
                        "Socket Type": port.get("socket_type"),
                        "Port": port.get("port"),
                        "Protocol": port.get("protocol"),
                        "Product Name": port.get("product_name"),
                        "Product Version": port.get("product_version"),
                        "Has Vulnerability": port.get("has_vulnerability", False),
                        "Confirmed Time": port.get("confirmed_time")
                    }
                    for port in data.get("current_opened_port", {}).get("data", [])
                ],
            "Remote Port": [
                    {
                        "Socket Type": port.get("socket_type"),
                        "Port": port.get("port"),
                        "Protocol": port.get("protocol"),
                        "Product Name": port.get("product_name"),
                        "Product Version": port.get("product_version"),
                        "Has Vulnerability": port.get("has_vulnerability", False),
                        "Confirmed Time": port.get("confirmed_time")
                    }
                    for port in data.get("remote_port", {}).get("data", [])
                ],
            "Vulnerability": [
                    {
                        "CVE ID": vuln.get("cve_id"),
                        "CWE IDs": vuln.get("cwe_ids", []),
                        "EDB IDs": vuln.get("edb_ids", []),
                        "Ports": {
                            "TCP": vuln.get("ports", {}).get("tcp", []),
                            "UDP": vuln.get("ports", {}).get("udp", [])
                        },
                        "CVSSv2 Vector": vuln.get("cvssv2_vector"),
                        "CVSSv2 Score": vuln.get("cvssv2_score", 0.0),
                        "CVSSv3 Vector": vuln.get("cvssv3_vector"),
                        "CVSSv3 Score": vuln.get("cvssv3_score", 0.0),
                        "Product Name": vuln.get("product_name"),
                        "Product Version": vuln.get("product_version"),
                        "Product Vendor": vuln.get("product_vendor")
                    }
                    for vuln in data.get("vulnerability", {}).get("data", [])
                ],
            "IDS": [
                    {
                        "Classification": ids.get("classification"),
                        "URL": ids.get("url"),
                        "Message": ids.get("message"),
                        "Source System": ids.get("source_system"),
                        "Confirmed Time": ids.get("confirmed_time")
                    }
                    for ids in data.get("ids", {}).get("data", [])
                ],
            "Scanning Record": [
                    {
                        "Log Date": scan.get("log_date"),
                        "Destination Port": scan.get("dst_port"),
                        "Protocol Type": scan.get("protocol_type"),
                        "User Agent": scan.get("user_agent"),
                        "Message": scan.get("message"),
                        "Confirmed Time": scan.get("confirmed_time")
                    }
                    for scan in data.get("scanning_record", {}).get("data", [])
                ],
            "IP Category": [
                    {
                        "Type": category.get("type"),
                        "Detect Source": category.get("detect_source"),
                        "Confirmed Time": category.get("confirmed_time")
                    }
                    for category in data.get("ip_category", {}).get("data", [])
                ]
        }

    elif section == 'ip/hosting':
        section_data["Hosting"] = {
        "IP": data.get("ip"),
        "Is Hosting": data.get("is_hosting", False),
        "Hosting Info": {
            "Hosting/Cloud As Name": data.get("hosting_info", {}).get("as_name_include_hosting_or_cloud"),
            "Domain Info": [
                {
                    "Email": domain.get("email"),
                    "Create Date": domain.get("create_date"),
                    "Registrar": domain.get("registrar"),
                    "Confirmed Time": domain.get("confirmed_time"),
                    "Domain": domain.get("domain")
                }
                for domain in data.get("hosting_info", {}).get("domain_exist_more_than_5", [])
            ],
            "Cloud IP Range Matching": {
                "IP Range": data.get("hosting_info", {}).get("cloud_ip_range_matching", {}).get("ip_range"),
                "Cloud Service": data.get("hosting_info", {}).get("cloud_ip_range_matching", {}).get("cloud_service")
            }
            }
        }

    section_data.update(section_data)

    return section_data

def parse_args(args):
    ip = None
    full_data = False
    ip_file = None
    sections = []
    help = (
    "usage: ./criminalip.py <ip> [-h] [-f] [-a] [-r] [-s] [-i] [-v] [-m] [-t] --file=[FILE]\n\n"
    "An API script to gather data from https://www.criminalip.io/\n\n"
    "optional arguments:\n"
    "  -h, --help         Show this help message and exit.\n"
    "  -f                 Retrieve the API full data.\n"
    "  -a                 Retrieve all sections data.\n"
    "  -r                 Retrieve full report data.\n"
    "  -s                 Retrieve report summary data.\n"
    "  -i                 Retrieve IP summary data.\n"
    "  -v                 Retrieve VPN data in detail.\n"
    "  -m                 Retrieve malicious info data in detail.\n"
    "  -t                 Retrieve hosting data in detail.\n"
    "  --file=[FILE]      Full path to a text file containing a ip name on each line.\n")
    
    section_map = {
        'r': 'asset/ip/report',
        's': "asset/ip/report/summary",
        'i': "asset/ip/summary",
        'v': "ip/vpn",
        'm': "ip/malicious-info",
        't': "ip/hosting"
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
    
    return ip, full_data, ip_file, sections

def fetch_data(ip, section):
    try:
        response = requests.get(f'https://api.criminalip.io/v1/{section}?ip={ip}&full=true', headers=headers)
        response.raise_for_status()
        data = response.json()
        return data

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        print(response.json())

try:
    ip, full_data, ip_file, sections = parse_args(sys.argv[1:])
    sections = sections or ["asset/ip/report/summary"]

    if not ip and not ip_file:
        ip = input("Enter your IP address here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if ip_file:
        with open(ip_file, 'r') as file:
            ips = [line.strip() for line in file if is_valid_ipv4(line.strip())]
    else:
        ips = [ip]

    for ip in ips:
        for section in sections:
            data = fetch_data(ip,section)
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
