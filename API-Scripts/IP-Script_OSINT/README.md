# IP Threat Intel Scripts

This repository contains various scripts for gathering threat intelligence related to IP addresses using different APIs. Each script sends input data to a respective API, retrieves the response, and _parses_ the output for easy analysis.

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

| Filename          | Threat Intel Name | API Documentation                   | Flags                              | Notes                                                                                             |
|-------------------|-------------------|-------------------------------------|------------------------------------|---------------------------------------------------------------------------------------------------|
| abuseipdb.py      | [AbuseIPDB](https://docs.abuseipdb.com/)  | https://docs.abuseipdb.com/ | -h, -f, --file=<file> |                                                                                                   |
| alienvault.py     | [AlienVault](https://otx.alienvault.com/) | https://otx.alienvault.com/assets/static/external_api.html#api_v1_search | -h, -f, -g, -c, -r, -m, -d, -u, -s, -a, --file=<file> |                                                                                                   |
| apivoid.py        | [APIVoid](https://www.apivoid.com/)       | https://docs.apivoid.com/    | -h, -f, --file=<file> |                                                                                                   |
| censys.py         | [Censys](https://censys.io/)              | https://search.censys.io/api          | -h, -f, --file=<file> |                                                                                                   |
| fraudguard.py     | [FraudGuard](https://www.fraudguard.io/)  | https://docs.fraudguard.io/  | -h, -f, --file=<file> |                                                                                                   |
| greynoise.py      | [GreyNoise](https://www.greynoise.io/)    | https://docs.greynoise.io/   | -h, -f, --file=<file> | Community and enterprise data parsing version are available. Make sure to activate the one you want by commenting/uncommenting. |
| ibmxforce.py      | [IBM X-Force](https://exchange.xforce.ibmcloud.com/) | https://api.xforce.ibmcloud.com/doc/ | -h, -f, --file=<file> |                                                                                                   |
| ipdata.py         | [IPData](https://ipdata.co/)              | https://docs.ipdata.co/docs/          | -h, -f, --file=<file> |                                                                                                   |
| ipinfo.py         | [IPInfo](https://ipinfo.io/)              | https://ipinfo.io/developers          | -h, -f, --file=<file> |                                                                                                   |
| maltiverse.py     | [Maltiverse](https://www.maltiverse.com/) | https://app.swaggerhub.com/apis-docs/maltiverse/api/1.1.2 | -h, -f, --file=<file> |                                                                                                   |
| proxycheck.py     | [ProxyCheck](https://proxycheck.io/)      | https://proxycheck.io/api/      | -h, -f, --file=<file> |                                                                                                   |
| shodan.py         | [Shodan](https://www.shodan.io/)          | https://developer.shodan.io/api      | -h, -f, --file=<file> | Lots of IPs may be found to be unavailable due to the free API key version.                     |
| threatminer.py    | [ThreatMiner](https://www.threatminer.org/) | https://www.threatminer.org/api.php | -h, -f, -w, -d, -u, -r, -s, -t, -a,--file=<file> |                                                                                                   |
| virustotal.py     | [VirusTotal](https://www.virustotal.com/) | https://docs.virustotal.com/reference/overview | -h, -f, --file=<file> |                                                                                                   |
| spamhaus.py       | [Spamhaus](https://spamhaus.com/) | https://docs.spamhaus.com/ | -h, -f, --file=<file> |                                                                                                   |
| criminalip.py       | [CriminalIP](https://www.criminalip.io/) | https://www.criminalip.io/developer/api/post-user-me | -h, -f, -a, -r, -s, -i, -v, -m, t, --file=<file> |                                            Currently has some problem and need some adjustment                                                       |
| opswat.py       | [MetaDefender Cloud](https://metadefender.opswat.com) | https://docs.opswat.com/mdcloud/metadefender-cloud-api-v4 | -h, -f, --file=<file> |                                            Will update in the future to have bulk upload                                                    |
| secfeed.py       | [SecureFeed](https://securefeed.com/) | https://securefeed.com/Content/Documentation | -h, -f, --file=<file> |                                                                                               |
| pulsedive.py       | [SecureFeed](https://pulsedive.com/) | https://pulsedive.com/api/ | -h, -f, --file=<file> |                                                                                             |
