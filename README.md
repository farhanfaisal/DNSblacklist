#DNSBlacklist project.

##Introduction.
	This project aims to be an assisting tool to setup your own DNS blacklisting in your enterprise 
	environment. While the DNS provide blacklisting service, it will provide a good and fast caching 
	for the enterprise DNS use. This tool will retrieve latest known malicious domains, and 
	generate configuration file for BIND or UNBOUND DNS server.

	This script utilizing unbound as local recursive DNS server for your environment.

##How it works

	The script will pull malicious domains from various sources, to be configured in an unbound/bind 
	DNS server. This server will be your internal DNS server in your environment. Any DNS request
	to malicious domain by any user in your environment will be handled by Unbound/BIND by returning 
	a specified IP, usually 127.0.0.1, or any 'blackhole' IP. You can point to another server to 
	monitor the malicious request

This include domain parser from various malicious domain provider
- http://www.malwaredomains.com/
- https://spyeyetracker.abuse.ch/blocklist.php?download=domainblocklist
- http://www.abuse.ch/zeustracker/blocklist.php?download=domainblocklist
- https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist
- https://isc.sans.edu/suspicious_domains.html#lists
- http://malc0de.com/bl/ZONES
- http://labs.sucuri.net/?malware
- www.malwareblacklist.com/mbl.xml
- http://www.malwarepatrol.net/cgi/submit?action=list_bind
- http://mtc.sri.com/live_data/malware_dns/
- http://exposure.iseclab.org/malware_domains.txt
- http://support.clean-mx.de/clean-mx/xmlviruses?format=xml&fields=review,url&response=alive
- http://www.nictasoft.com/ace/malware-urls/
- http://mirror1.malwaredomains.com/files/spywaredomains.zones

##Main features
- Configurables of which domain sources to be used.
- Option for output format, Unbound or Bind DNS server (Unbound by default)
- Domain permanent whitelisting and blacklisting

The main script is preparation.sh, which generate a configuration 
file for unbound DNS server. You can choose BIND format output as well

##How to use
 - Pull to /etc/unbound/
 - Edit /etc/unbound/unbound.conf according to your server environment. (Note the reference to "/etc/unbound/blackhole/blacklisted_domains.conf")
 - Run preparation.sh in /etc/unbound/blackhole/. Your "/etc/unbound/blackhole/blacklisted_domains.conf" will be created automatically.
 - run unbound-checkconf to verify the config file
 - Restart unbound for the config file to be effective.


####@2014
