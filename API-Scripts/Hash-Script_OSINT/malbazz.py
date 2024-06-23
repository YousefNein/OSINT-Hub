#!/usr/bin/python3

import requests
import json
import re
choice = input("You want to seach by hash or by URL?\nEnter (1) for URL or (2) for hash\n")
if choice == '1':
    url = input("Enter the URL you want to scan here:\n")
    data = {'url' : url}
    response = requests.post('https://urlhaus-api.abuse.ch/v1/url/', data)
    json_response = response.json()
    if json_response['query_status'] == 'ok':
        print(json.dumps(json_response, indent=4, sort_keys=False))
    elif json_response['query_status'] == 'no_results':
        print("No results")
    else:
        print("Something went wrong")
elif choice == "2":
    file_hash = input("Enter the file hash you want to scan here:\n")
    if re.search(r"^[A-Za-z0-9]{32}$", file_hash):
        hash_algo = 'md5_hash'
    elif re.search(r"^[A-Za-z0-9]{64}$", file_hash):
        hash_algo = 'sha256_hash'
    else:
        print("Invalid file hash provided")
    data = {hash_algo : file_hash}
    response = requests.post('https://urlhaus-api.abuse.ch/v1/payload/', data)
    json_response = response.json()
    if json_response['query_status'] == 'ok':
        print(json.dumps(json_response, indent=4, sort_keys=False))
    elif json_response['query_status'] == 'no_results':
        print("No results")
    else:
        print("Something went wrong")