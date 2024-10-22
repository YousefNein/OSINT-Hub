#!/bin/python3

import requests
import os
import argparse
import sys
import re
import json
import mimetypes
import hashlib
from dotenv import load_dotenv
from time import sleep
from datetime import datetime

load_dotenv()

url = "https://www.virustotal.com/api/v3/"

headers = {
    "accept": "application/json",
    'x-apikey': os.environ.get("VIRUS_TOTAL_API")
}

def format_data(data):
    formatted_data = json.dumps(data, indent=4, sort_keys=False)
    return formatted_data

def is_valid_ipv4(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if pattern.match(ip):
        return all(0 <= int(part) < 256 for part in ip.split('.'))
    return False

def is_valid_url(url):
    pattern = re.compile(
        r'^(?:http|ftp)s?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(pattern, url) is not None

def is_valid_hash(hash):
    patterns = {
        'md5': r'^[a-f0-9]{32}$',
        'sha1': r'^[a-f0-9]{40}$',
        'sha256': r'^[a-f0-9]{64}$',
        'sha512': r'^[a-f0-9]{128}$'
    }

    for pattern in patterns.values():
        if re.match(pattern, hash, re.IGNORECASE):
            return True
    return False

def fetch_data_file(file_location):
    try:
        mime_type, _ = mimetypes.guess_type(file_location)
        if not mime_type:
            mime_type = "application/octet-stream"
        files = { "file": (file_location, open(file_location, "rb"), mime_type) }
        response = requests.post(f"{url}/files", headers=headers, files=files)
        response.raise_for_status()
        response = response.json()
        analysis_id = response.get("data", {}).get("id")
        print(f"Analysing the file with ID {analysis_id}...\n")
        while True:
            response = requests.get(f"{url}/analyses/{analysis_id}", headers=headers)
            response.raise_for_status()
            data = response.json()
            if data.get("data", {}).get("attributes", {}).get("status") != "queued":
                return data
            sleep(5)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        print(response.json())

def fetch_data_ip(ip):
    return

def fetch_data_file_hash(file_location):
    hash_function = hashlib.new('sha256')
    
    with open(file_location, 'rb') as file:
        while chunk := file.read(8192):
            hash_function.update(chunk)
    sha256_hash = hash_function.hexdigest()
    print(sha256_hash)

def filter_data(data):
    if data is None:
        return None
    
    attributes = data.get("data", {}).get("attributes")
    meta = data.get("meta", {})
    date = attributes.get("date")
    date = datetime.fromtimestamp(date).strftime('%Y-%m-%d')

    filterd_data = {
        "Hash": meta.get("file_info").get("sha256"),
        "Last Analysis Date": date,
        "Size": meta.get("file_info").get("size"),
        "Harmless": attributes.get("stats", {}).get("harmless"),
        "Malicious": attributes.get("stats", {}).get("malicious"),
        "Suspicious": attributes.get("stats", {}).get("suspicious"),
        "Timeout": attributes.get("stats", {}).get("timeout"),
        "Undetected": attributes.get("stats", {}).get("undetected"),
    }

    return filterd_data

def main():
    parser = argparse.ArgumentParser(description="Upload a file to VirusTotal.")
    parser.add_argument("-f", "--file", help="Path to the file to be uploaded.")
    parser.add_argument("--full", help="Retrieve the API full data.", action="store_true")
    parser.add_argument("-b", "--behavior", help="Retrieve all behavior data.", action="store_true")
    parser.add_argument("-s", "--summary", help="Retrieve behavior summary data.", action="store_true")
    
    args = parser.parse_args()
    if args.file:
        if args.behavior:
            data = fetch_data_file_hash(args.file)
            # print(format_data(data))
        elif args.summary:
            data = fetch_data_file(args.file, "/behaviour_summary")
            print(format_data(data))
        else:
            data = fetch_data_file(args.file)
            if args.full:
                print(format_data(data))
            else:
                print(format_data(filter_data(data)))
    else:
        print("Please provide either a file path to upload or an analysis ID to fetch results.")
        sys.exit(1)

if __name__ == "__main__":
    main()