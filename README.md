# simple export

Simple, in that there is nothing to install and no 3rd partly libraries were harmed in the creation of this script. 

This script will: 
 - export vulnerabilities from Tenable.io
 - flatten nested json into a flat record  
 - rewrite column headers based on criteria in the config file
 - write records out to a csv file

configuration
---
The config file needs to be in the following format:

```angular2html
ACCESS_KEY=9a09bb6a8f...
SECRET_KEY=0f262ed976...

rename_columns:
    asset.ipv4                   : IP
    asset.hostname               : Hostname
    asset.operating_system       : OS
    plugin.name                  : Vulnerability Title
    severity                     : Severity
    plugin.cvss_base_score       : CVSS Score
    plugin.exploit_available     : Exploit Exists? (YES/NO)
    state                        : Vulnerability status (Fixed/Active)
    first_found                  : Date Vuln was detected
    last_fixed                   : Vuln Remediation date
```

usage
---
```angular2html

Usage: export_vulns.py [-h] [--config-path CONFIG_PATH] [--config-file CONFIG_FILE] [--output-path OUTPUT_PATH]
                       [--output-file OUTPUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  --config-path CONFIG_PATH
                        Location of the config file.
  --config-file CONFIG_FILE
                        Name of config file (defaults to .env).
  --output-path OUTPUT_PATH
                        Path to write output file.
  --output-file OUTPUT_FILE
                        Output file name.

```
