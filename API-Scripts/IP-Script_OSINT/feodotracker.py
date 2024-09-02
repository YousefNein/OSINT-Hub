#!/bin/python3

import requests
import sys
import json
import re
from bs4 import BeautifulSoup
from dotenv import load_dotenv

load_dotenv()

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
    
    filtered_data = {
    "IP": data.get("IP"),
    "Hostname": data.get("Hostname"),
    "Country": data.get("Country"),
    "AS Name": data.get("AS name"),
    "CC_details": data.get("C&C details")[0] if data.get("C&C details") else None
}
    filtered_data = {k: v for k, v in filtered_data.items() if v is not None}
    return filtered_data

def parse_args(args):
    ip = None
    full_data = False
    ip_file = None
    help = """
usage: ./fedotracker.py <ip> [-h] [-f] --file==[FILE]

An API script to gather data from https://feodotracker.abuse.ch/

optional arguments:
  -h, --help      Show this help message and exit.
  -f              Retrieve the API full data.
  --file==[FILE]  Full path to a test file containing an IP address on each line.
  """
    
    for arg in args:
        if arg == "--help" or arg == "-h":
            print(help)
            sys.exit(0)
        elif is_valid_ipv4(arg):
            ip = arg
        elif arg == '-f':
            full_data = True
        elif arg.startswith("--file="):
            ip_file = arg.split("=", 1)[1]
        elif arg.startswith('-'):
            print(f"Error: Unknown flag {arg}")
            print(help)
            sys.exit(1)
        else:
            print(f"Error: Unknown input {arg}")
            print(help)
            sys.exit(1)
    
    return ip, full_data, ip_file

def parse_data(data):
    soup = BeautifulSoup(data, 'html.parser')

    result = {
        'IP': "IP not found",
        'Hostname': None,
        'AS number': None,
        'AS name': None,
        'Country': None,
        'First seen': None,
        'Last online': None,
        'C&C details': []
    }

    table = soup.find_all('table')
    if table:
        main_table = table[0]  
        rows = main_table.find_all('tr')
        if len(rows) >= 6:  
            ip_address = rows[0].find_all('td')[0].text.strip()
            if ip_address:
                result['IP'] = ip_address
                result['Hostname'] = rows[1].find_all('td')[0].text.strip() or None
                result['AS number'] = rows[2].find_all('td')[0].text.strip() or None
                result['AS name'] = rows[3].find_all('td')[0].text.strip() or None
                result['Country'] = rows[4].find_all('td')[0].text.strip() or None
                result['First seen'] = rows[5].find_all('td')[0].text.strip() or None
                result['Last online'] = rows[6].find_all('td')[0].text.strip() or None

    c2c_table = soup.find('table', {'id': 'c2c'})
    if c2c_table:
        c2c_rows = c2c_table.find('tbody').find_all('tr')
        for row in c2c_rows:
            cols = row.find_all('td')
            if len(cols) >= 7:
                c2c_details = {
                    'Port': cols[2].text.strip() or None,
                    'Malware': cols[3].text.strip() or None,
                    'Status': cols[4].text.strip() or None,
                    'Abuse complaint sent': cols[5].text.strip() or None,
                }
                result['C&C details'].append(c2c_details)

    return result

def fetch_data(ip):
    try:
        response = requests.get(f'https://feodotracker.abuse.ch/browse/host/{ip}/')
        return response.text

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

try:
    ip, full_data, ip_file = parse_args(sys.argv[1:])

    if not ip and not ip_file:
        ip = input("Enter your IP address here:\n")
        full_data = input("Do you want the full data to be shown? Y/n\n").lower() in ['y', 'yes', '']

    if ip_file:
        with open(ip_file, 'r') as file:
            ips = [line.strip() for line in file if is_valid_ipv4(line.strip())]
    else:
        ips = [ip]

    for ip in ips:
        data = fetch_data(ip)
        data = parse_data(data)
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
