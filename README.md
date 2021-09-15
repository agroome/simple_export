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
License
---
MIT License

Copyright (c) 2021 Andy Groome

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
