# SAP-brute
SAP Netweaver Login Bruteforcer.

```
usage: SAP-brute.py [-h] [-u URL] [-f FILE] [-p PROXY]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     URL to test
  -f FILE, --file FILE  File of urls
  -p PROXY, --proxy PROXY
                        Proxy for debugging
```

Single Site
---
```
python3 SAP-brute.py -u http://whastever.com
```

Multiple Sites
---
```
python3 SAP-brute.py -f sites.txt
```

