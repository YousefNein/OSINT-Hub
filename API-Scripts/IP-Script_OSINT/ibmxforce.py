#!/bin/python3

import requests
import os
import json
import sys

base_url_xf = "https://api.xforce.ibmcloud.com/api"

headers_xf = {
    'accept': 'application/json',
    'Authorization': os.environ.get("IBM_XFORCE_API")
}

try:
    if len(sys.argv) > 1:
        ip = sys.argv[1]
    else:
        ip = input("Enter your IP address here:\n")

    url_xf = f'{base_url_xf}/ipr/{ip}'
    response_xf = requests.get(url_xf, headers=headers_xf)
    json_data_xf = response_xf.json()
    print(json_data_xf)
    max_score_ip = max(json_data_xf["history"], key=lambda x: x.get('score', 0))
    geolocation = json_data_xf.get("geo")
    categories = json_data_xf.get("cats")
    category_descriptions = json_data_xf.get("categoryDescriptions")
    if not categories or not category_descriptions:    
        categories = max_score_ip["cats"]
    category_descriptions = max_score_ip["categoryDescriptions"]
    reason_description = max_score_ip["reasonDescription"]
    score = max_score_ip["score"]
    response_xf = {
        "geolocation": geolocation,
        "categories": categories,
        "categoryDescriptions": category_descriptions,
        "reasonDescription": reason_description,
        "score": score,
        "fullData_xf": json_data_xf
    }

except KeyboardInterrupt:
    print("\nProcess interrupted by user.")
except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")