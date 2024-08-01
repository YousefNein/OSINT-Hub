# URL Threat Intel Scripts

This repository contains various scripts for gathering threat intelligence related to URLs using different APIs. Each script sends input data to a respective API, retrieves the response, and _parses_ the output for easy analysis.

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

| Filename            | Threat Intel Name                           | API Documentation                                                                 | Flags                              | Status             | Notes                                                                                     |
|---------------------|---------------------------------------------|-----------------------------------------------------------------------------------|------------------------------------|--------------------|-------------------------------------------------------------------------------------------|
| alienvault.py       | [AlienVault](https://otx.alienvault.com/)   | https://otx.alienvault.com/assets/static/external_api.html#api_v1_search           | -h, -f, -g, -u, -a, --file=<file> | Ready              |                                                                                           |
| apivoid.py          | [APIVoid](https://www.apivoid.com/)         | https://docs.apivoid.com/                                                          | -h, -f, --file=<file>               | Ready              |                                                                                           |
| hybrid-analysis.py  | [Hybrid Analysis](https://www.hybrid-analysis.com/) | https://www.hybrid-analysis.com/docs/api/v2                                         | -h, -f, --file=<file>               | Ready              |                                                                                           |
| ibmxforce.py        | [IBM X-Force](https://exchange.xforce.ibmcloud.com/) | https://api.xforce.ibmcloud.com/doc/                                              | -h, -f, -r, -m, -a, --file=<file>               | Ready |                                                                                           |
| maltiverse.py       | [Maltiverse](https://www.maltiverse.com/)   | https://app.swaggerhub.com/apis-docs/maltiverse/api/1.1.2                          | -h, -f, --file=<file>               | Ready              |                                                                                           |
| urlhaus.py          | [URLhaus](https://urlhaus.abuse.ch/)        | https://urlhaus.abuse.ch/api/                                                      | -h, -f, --file=<file>               | Ready              |                                                                                           |
| urlscanio.py        | [urlscan.io](https://urlscan.io/)           | https://urlscan.io/about-api/                                                      | -h, -f, --file=<file>               | Ready              |                                                                                           |
| virustotal.py       | [VirusTotal](https://www.virustotal.com/)   | https://docs.virustotal.com/reference/overview                                         | -h, -f, --file=<file>               | Ready              |                                                                                           |
