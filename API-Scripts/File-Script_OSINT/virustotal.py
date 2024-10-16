#!/bin/python3

import requests
import os
import argparse
import sys
import json
import mimetypes
from dotenv import load_dotenv
from time import sleep

load_dotenv()

url = "https://www.virustotal.com/api/v3/"

headers = {
    "accept": "application/json",
    'x-apikey': os.environ.get("VIRUS_TOTAL_API")
}

def format_data(data):
    formatted_data = json.dumps(data, indent=4, sort_keys=False)
    return formatted_data

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
        print(f"Analysing the URL with ID {analysis_id}...\n")
        response = requests.get(f"{url}/analyses/{analysis_id}", headers=headers)
        response.raise_for_status()
        data = response.json()
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

def filter_data(data):
    if data is None:
        return None
    
    filterd_data = {
        
    }

def main():
    parser = argparse.ArgumentParser(description="Upload a file to VirusTotal.")
    parser.add_argument("-f", "--file", help="Path to the file to be uploaded.")
    
    args = parser.parse_args()
    if args.file:
        data = fetch_data_file(args.file)
        print(format_data(data))
    else:
        print("Please provide either a file path to upload or an analysis ID to fetch results.")
        sys.exit(1)

if __name__ == "__main__":
    main()