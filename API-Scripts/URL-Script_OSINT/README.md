# URL Threat Intel Scripts

This repository contains various scripts for gathering threat intelligence related to URLs using different APIs. Each script sends input data to a respective API, retrieves the response, and _parses_ the output for easy analysis.

## How to Use

1. **Set Up Environment Variables:**
   - Copy .env.copy in the API-Scripts directory if you haven't done that already.
    ```bash
    cp env.copy .env
    ```

   - Add your API keys in the `.env` file with the appropriate variable names, for example:
     ```
     VIRUS_TOTAL_API=your_virustotal_api_key
     ```
     Use the links that are next to every threat intel name to generate an API key.

2. **Run a Script:**
   - First you will need to install the requirements in the API-Scripts directory:
    ```bash
    pip install -r requirements.txt
    ```

   - You can run any script by using Python. For example, to run the `virustotal.py` script, use the following command:
     ```python
     python3 virustotal.py <url> [-f] [--file=<file>]
     ```
     Or you can run the script without an input.
     ```python
     ./virustotal.py
     ```

     - `<url>`: The URL you want to check.
     - `-f`: (Optional) Retrieve the full unparsed API data.
     - `--file=<file>`: (Optional) Full path to a file containing URLs, one per line.

     For more info, please use the flag h for help.
     ```python
     ./virustotal.py [-h] [--help]
     ```

### Example

```bash
python3 virustotal.py http://example.com -f
```

## Script Table

| Filename            | Threat Intel Name                           | API Documentation                                                                 | Flags                              | Notes                                                                                     |
|---------------------|---------------------------------------------|-----------------------------------------------------------------------------------|------------------------------------|-------------------------------------------------------------------------------------------|
| alienvault.py       | [AlienVault](https://otx.alienvault.com/)   | https://otx.alienvault.com/assets/static/external_api.html#api_v1_search           | -h, -f, -g, -u, -a, --file=<file> |                                                                                           |
| apivoid.py          | [APIVoid](https://www.apivoid.com/)         | https://docs.apivoid.com/                                                          | -h, -f, --file=<file>               |                                                                                           |
| hybrid-analysis.py  | [Hybrid Analysis](https://www.hybrid-analysis.com/) | https://www.hybrid-analysis.com/docs/api/v2                                         | -h, -f, --file=<file>               |                                                                                           |
| ibmxforce.py        | [IBM X-Force](https://exchange.xforce.ibmcloud.com/) | https://api.xforce.ibmcloud.com/doc/                                              | -h, -f, -r, -m, -a, --file=<file> |                                                                                           |
| maltiverse.py       | [Maltiverse](https://www.maltiverse.com/)   | https://app.swaggerhub.com/apis-docs/maltiverse/api/1.1.2                          | -h, -f, --file=<file>               |                                                                                           |
| urlhaus.py          | [URLhaus](https://urlhaus.abuse.ch/)        | https://urlhaus.abuse.ch/api/                                                      | -h, -f, --file=<file>               |                                                                                           |
| urlscanio.py        | [urlscan.io](https://urlscan.io/)           | https://urlscan.io/about-api/                                                      | -h, -f, --file=<file>               |                                                                                           |
| virustotal.py       | [VirusTotal](https://www.virustotal.com/)   | https://docs.virustotal.com/reference/overview                                         | -h, -f, -a, -g, -b, --file=<file>               |                The b flag needs parsing                                                                           |
| spamhaus.py         | [SPAMHAUS](https://spamhaus.com/)           | https://docs.spamhaus.com/                                                           | -h, -f, -a, -l, -t, --file=<file> | Will work on it in the future when the beta ends.                                       |
| opswat.py       | [MetaDefender Cloud](https://metadefender.opswat.com) | https://docs.opswat.com/mdcloud/metadefender-cloud-api-v4 | -h, -f, --file=<file> |                                            Will update in the future to have bulk upload 
| checkphish.py       | [CHECKPHISH](https://app.checkphish.ai/) | https://bolster.ai/kbarticles/scan-apis-for-checkphish-users | -h, -f, -a, -q, -u, --file=<file> |                                        
| criminalip.py       | [Criminal IP](https://www.criminalip.io/) | https://www.criminalip.io/developer/api/post-domain-scan | -h, -f, --file=<file> |      Needs filtering                                  