# Domain Threat Intel Scripts

This repository contains various scripts for gathering threat intelligence related to domains using different APIs. Each script sends input data to a respective API, retrieves the response, and _parses_ the output for easy analysis.

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
     python3 virustotal.py <domain> [-f] [--file=<file>]
     ```
     Or you can run the script without an input.
     ```python
     ./virustotal.py
     ```

     - `<domain>`: The domain you want to check.
     - `-f`: (Optional) Retrieve the full unparsed API data.
     - `--file=<file>`: (Optional) Full path to a file containing domains, one per line.

     For more info, please use the flag h for help.
     ```python
     ./virustotal.py [-h] [--help]
     ```

### Example

```bash
python3 virustotal.py example.com -f
```

## Script Table

| Filename          | Threat Intel Name | API Documentation                   | Flags                              | Notes                     |
|-------------------|-------------------|-------------------------------------|------------------------------------|---------------------------|
| alienvault.py     | [AlienVault](https://otx.alienvault.com/) | https://otx.alienvault.com/assets/static/external_api.html#api_v1_search | -h, -f, -g, -c, -W, -m, -d, -u, -s, -a, --file=<file> |                             |
| apivoid.py        | [APIVoid](https://www.apivoid.com/)       | https://docs.apivoid.com/    | -h, -f, --file=<file> |                             |
| censys.py         | [Censys](https://censys.io/)              | https://search.censys.io/api          | -h, -f, --file=<file> |                             |
| hostinfo.py       | [HostInfo](https://host.io/)              | https://host.io/docs/api | -h, -f, w, d, r, -a, --file=<file> |                             |
| ibmxforce.py      | [IBM X-Force](https://exchange.xforce.ibmcloud.com/) | https://api.xforce.ibmcloud.com/doc/ | -h, -f, --file=<file> |                             |
| maltiverse.py     | [Maltiverse](https://www.maltiverse.com/) | https://app.swaggerhub.com/apis-docs/maltiverse/api/1.1.2 | -h, -f, --file=<file> | Only checks for the hostnames.                             |
| sectrails.py      | [SecurityTrails](https://securitytrails.com/) | https://docs.securitytrails.com/docs | -h, -f, -d, -s, -a, --file=<file> |                             |
| shodan.py         | [Shodan](https://www.shodan.io/)          | https://developer.shodan.io/api      | -h, -f, --file=<file> | Only checks for the hostnames and will probably need a premium API key.                            |
| threatminer.py    | [ThreatMiner](https://www.threatminer.org/) | https://www.threatminer.org/api.php | -h, -f, -w, -d, -u, -r, -s, -t, -a,--file=<file> |                             |
| virustotal.py     | [VirusTotal](https://www.virustotal.com/) | https://docs.virustotal.com/reference/overview | -h, -f, --file=<file> |                             |
| spamhaus.py       | [SPAMHAUS](https://spamhaus.com/) | https://docs.spamhaus.com/ | -h, -f, -a, -g, -s, -n, -i, -o, -m, -u, --file=<file> |                             |
| fullhunt.py       | [FullHunt](https://fullhunt.io/) | https://api-docs.fullhunt.io/ | -h, -f, -a, -d, -s, -o, --file=<file> |                             |
