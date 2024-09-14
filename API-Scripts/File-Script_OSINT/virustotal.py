#!/bin/python3

import requests
import os
import argparse
import sys
import json
from dotenv import load_dotenv
from time import sleep

load_dotenv()
url = "https://www.virustotal.com/api/v3/"

headers = {
    "accept": "application/json",
    "content-type": "multipart/form-data",
    'x-apikey': os.environ.get("VIRUS_TOTAL_API")
}

file_location = False

def fetch_data(target):
    try:
        if target is True:
            files = { "file": (file_location, open(file_location, "rb"), "text/csv") }
            response = requests.post(f"{url}/files", headers=headers, file=files)
            response.raise_for_status()
            response = response.json()
            analysis_id = response.get("data", {}).get("id")
            print(f"Analysing the URL with this {analysis_id}...\n")
        else:
            analysis_id = target
            response = requests.get(f"{url}/analyses/{analysis_id}", headers=headers)
            response.raise_for_status()
            data = response.json()
            print(data)
            return data
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

def main():
    fetch_data()

main()