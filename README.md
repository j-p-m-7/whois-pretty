# whois-pretty

### Description

CLI tool that outputs RDAP info in pretty format

### Installation

Can be installed with uv via:

```bash
> uv tool install git+https://github.com/j-p-m-7/whois-pretty
```

### Sample usage

```bash
> whois 17.248.195.64
```

```bash
WHOIS Summary for 17.248.195.64

	CIDR:           17.0.0.0/8
	IP Range:       17.0.0.0 - 17.255.255.255
	Net Name:       APPLE-WWNET
	Organization:   Apple Inc.
	Country:        ['', '', '', '', '', '', '']
	Status:         active
	Registered:     1990-04-16T00:00:00-04:00
	Last Updated:   2025-04-02T12:59:34-04:00
	Geofeed:        Geofeed https://ip-geolocation.apple.com
	Abuse Email:    N/A
	Tech Contact:   ip-hostmaster@group.apple.com

Source: https://rdap.arin.net/registry/ip/17.0.0.0
```