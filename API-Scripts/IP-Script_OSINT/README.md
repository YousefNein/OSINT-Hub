# IP Threat Intel Scripts

This repository contains various scripts for gathering threat intelligence related to IP addresses using different APIs. Each script sends input data to a respective API, retrieves the response, and _parses_ the output for easy analysis.

## How to Use

1. **Set Up Environment Variables:**
   - Add your API keys in the `.env` file with the appropriate variable names, for example:
     ```
     VIRUS_TOTAL_API=your_virustotal_api_key
     ```
     Use the links that are next to every threat intel name to generate an API key.

2. **Run a Script:**
   - You can run any script by using Python. For example, to run the `virustotal.py` script, use the following command:
     ```python
     python3 virustotal.py <ip> [-f] [--file=<file>]
     ```
     Or you can run the script without an input.
     ```python
     ./virustotal.py
     ```

     - `<ip>`: The IP address you want to check.
     - `-f`: (Optional) Retrieve the full unparsed API data.
     - `--file=<file>`: (Optional) Full path to a file containing IP addresses, one per line.

     For more info, please use the flag h for help.
     ```python
     ./virustotal.py [-h] [--help]
     ```

### Example

```bash
python3 virustotal.py 8.8.8.8 -f
```

## Script Table

| Filename          | Threat Intel Name | API Documentation                   | Flags                              | Status          | Notes                     |
|-------------------|-------------------|-------------------------------------|------------------------------------|-----------------|---------------------------|
| abuseipdb.py      | [AbuseIPDB](https://docs.abuseipdb.com/)  | https://docs.abuseipdb.com/ | -h, -f, --file=<file> | Ready            |                             |
| alienvault.py     | [AlienVault](https://otx.alienvault.com/) | https://otx.alienvault.com/assets/static/external_api.html#api_v1_search | -h, -f, -g, -c, -r, -m, -d, -u, -s, a, --file=<file> | Ready |                             |
| apivoid.py        | [APIVoid](https://www.apivoid.com/)       | https://docs.apivoid.com/    | -h, -f, --file=<file> | Ready            |                             |
| censys.py         | [Censys](https://censys.io/)              | https://search.censys.io/api          | -h, -f, --file=<file> | Ready |                             |
| fraudguard.py     | [FraudGuard](https://www.fraudguard.io/)  | https://docs.fraudguard.io/  | -h, -f, --file=<file> | Ready            |                             |
| greynoise.py      | [GreyNoise](https://www.greynoise.io/)    | https://docs.greynoise.io/   | -h, -f, --file=<file> | Ready            | Community and enterprise data parsing version are avaliable. Make sure to activiate the one you want by commenting/uncommenting.                            |
| ibmxforce.py      | [IBM X-Force](https://exchange.xforce.ibmcloud.com/) | https://api.xforce.ibmcloud.com/doc/ | -h, -f, --file=<file> | Under construction |                             |
| ipdata.py         | [IPData](https://ipdata.co/)              | https://docs.ipdata.co/docs/          | -h, -f, --file=<file> | Ready            |                             |
| ipinfo.py         | [IPInfo](https://ipinfo.io/)              | https://ipinfo.io/developers          | -h, -f, --file=<file> | Ready            |                             |
| maltiverse.py     | [Maltiverse](https://www.maltiverse.com/) | https://app.swaggerhub.com/apis-docs/maltiverse/api/1.1.2 | -h, -f, --file=<file> | Ready |                             |
| proxycheck.py     | [ProxyCheck](https://proxycheck.io/)      | https://proxycheck.io/api/      | -h, -f, --file=<file> | Ready            |                             |
| shodan.py         | [Shodan](https://www.shodan.io/)          | https://developer.shodan.io/api      | -h, -f, --file=<file> | Ready            | Lots of IPs may be found to be unavaliable due to the free API key version.                            |
| threatminer.py    | [ThreatMiner](https://www.threatminer.org/) | https://www.threatminer.org/api.php | -h, -f, -w, -d, -u, -r, -s, -t, a,--file=<file> | Ready |                             |
| virustotal.py     | [VirusTotal](https://www.virustotal.com/) | https://gtidocs.virustotal.com/ | -h, -f, --file=<file> | Ready            |                             |
