# SubFuz - A Subdomain Fuzzer
SubFuz is a fuzzing tool used for enumerating subdomains through multiple methods. 
This tool has various buildt in enumeration methods, at the same time as plugin support to enrich your result from different 3rd party sources. SubFuz accepts internationalized domain name (IDN) allowing you to scan domains like  пример.example, 例.example, мысал.example - as well as use UTF-8 based words in your fuzzing dictionary.

### Requirements
[![](https://img.shields.io/badge/python-2.7-blue.svg)](https://www.python.org/download/releases/2.7/)

Currently tested on Linux with python 2.7, will add better support for Windows and Python 3 soon.
```
sudo apt-get install python python-pip
git clone https://github.com/netsecurity-as/subfuz/
cd subfuz
pip install -r requirements.txt
```

### Usage
```
$ python subfuz.py -h
usage: subfuz.py [-h] [-d TARGET] [-l TARGET_LIST] [-w DICTIONARY]
                 [-o LOG_FILENAME] [-csv CSV_FILENAME] [-dns DNS]
                 [-protocol PROTOCOL] [-record RECORD] [-p P] [-z Z] [-r R]
                 [-t T] [-zone] [-ptr] [-quiet] [-all] [-virustotal]

required arguments:
  -d TARGET           Specify domain to fuzz, or..
  -l TARGET_LIST      Specify list of domains to fuzz

optional arguments:
  -w DICTIONARY       Specify fuzzing dictionary to use
  -o LOG_FILENAME     Write output to a file
  -csv CSV_FILENAME   Write output to a csv file
  -dns DNS            Override DNS server to query    [ None ]
  -protocol PROTOCOL  Override DNS protocol           [ None ]
  -record RECORD      Override DNS query record       [ None ]
  -p P                DNS timeout                     [ 3 ] sec
  -z Z                DNS request throttle            [ 0 ] ms
  -r R                DNS retries if failed           [ 3 ]
  -t T                Threads active                  [ 5 ]
  -zone               Disable Zone Transfer testing
  -ptr                Disable PTR check on related domains on the current /24 network
  -quiet              Suppress terminal output

plugins:
  -all                Enable all plugins
  -<plugin name>      <plugin info text>
```

### Configuration
See configuration [**config.json**](/config.json) to customizing default options, enabling / disabling plugins.

| Parameter | Default | Description |
| ------ | ------ | ------ |
| threads | 5 | Number of paralell threads to run scans with |
| dns_fallback | 8.8.8.8 | Fallback DNS server to resolve queries |
| dns_fallback_protocol | UDP | Fallback protocol to resolv with |
| dns_fallback_record | ANY | Fallback record type to resolv with |
| dns_override | null | Permanently override DNS server |
| dns_override_protocol | null | Permanently override DNS protocol |
| dns_override_record | null | Permanently override DNS record |
| throttle | 0 | Ratelimit each thread by x milliseconds |
| timeout | 3 | DNS query timeout |
| retry | 3 | Amount of retries on failed queries |
| deep_domains | N/A | Additional Tests performed on located subdomains.e.g. admin.subdomain.domain.com
| txt_record_search | N/A | Display and log matching TXT records |

### Plugins
For plugin developement or contributions, see [/plugins/README.md](/plugins/README.md) for how to get started.
SubFuz is currently extended with the following plugins:

| Plugin | README | Author |
| ------ | ------ | ------ |
| VirusTotal | [/plugins/virustotal/README.md](plugins/virustotal/README.md) | [Eplox](https://github.com/Eplox/) |

### Recommendations
Grab the domain fuzzing lists from Daniel Miessler repository: https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS

Included DNS wordlist is based on this source. 

### License
This project is licensed under the [GPL license](/LICENSE.md). 

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
