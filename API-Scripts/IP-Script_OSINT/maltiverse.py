#!/bin/python3

import requests
import json
import os
import sys
from dotenv import load_dotenv

load_dotenv()

try:
    if len(sys.argv) > 1:
        ip = sys.argv[1]
    else:
        ip = input("Enter your IP address here:\n")
    api_key = os.environ.get("MALTIVERSE")
    url = f'https://api.maltiverse.com/ip/{ip}'
    headers = { 'Authorization':'Bearer ' + api_key }
    response = requests.get(url, headers=headers)
    parsed = json.loads(response.text)
    as_name = parsed.get("as_name")
    country = parsed.get("country_code")
    asn_cidr = parsed.get("asn_cidr")
    print(as_name)
    
    ask = input("Do you want the full data to be shown? Y/n\n")
    if ask.lower() == "y" or ask == "": 
        print(json.dumps(parsed, indent=4, sort_keys=True))
    elif ask.lower() == "n":
        pass
    else:
        print("A wrong input. Choose Y or N")

except KeyboardInterrupt:
    print("\nProcess interrupted by user.")
except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")