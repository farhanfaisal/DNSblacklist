#!/bin/bash
today=`date "+%Y-%m-%d-%H-%M-%S"`

BASE="/etc/unbound"
FOLDER_BL="blackhole"

#### Notes
###	http://www.digriz.org.uk/network-layer-protection/dns
###	https://calomel.org/unbound_dns.html

########## Configurations
#	http://dns-bh.sagadc.org/domains.txt / http://www.malwaredomains.com/
SAGADC=1
#	https://spyeyetracker.abuse.ch/blocklist.php?download=domainblocklist
SPYEYE=1
#	http://www.abuse.ch/zeustracker/blocklist.php?download=domainblocklist
ZEUSTRACKER=1
#	https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist
PALEVOTRACKER=1
#	https://isc.sans.edu/suspicious_domains.html#lists
ISCSANS=1
#	http://malc0de.com/bl/ZONES
MALCODE=1
# 	http://labs.sucuri.net/?malware
SUCURI=1
#	www.malwareblacklist.com/mbl.xml
MALWAREBLACKLIST=1
#	http://www.malwarepatrol.net/cgi/submit?action=list_bind
MALWAREPATROL=1
#	http://mtc.sri.com/live_data/malware_dns/
MTC_SRI=1
#	http://exposure.iseclab.org/malware_domains.txt
ISECLAB=1
#	http://support.clean-mx.de/clean-mx/xmlviruses?format=xml&fields=review,url&response=alive
CLEANMX=0
#	http://www.nictasoft.com/ace/malware-urls/
NICTASOFT=1
#	http://mirror1.malwaredomains.com/files/spywaredomains.zones
MALWAREDOMAINS_SPY=1


## Choose which DNS server are you using, BIND of UNBOUND
DNSSERVER="unbound" # bind or unbound

## Delete all downloaded tmp files?
DELETE=1

############################################################
############	END OF CONFIGURABLE OPTIONS ################
############################################################

if [ ! -d $BASE/$FOLDER_BL/backup ]; then
	mkdir -p $BASE/$FOLDER_BL/backup
fi

## Backing up previous files.
mv $BASE/$FOLDER_BL/master.list $BASE/$FOLDER_BL/backup/master.list.$today.txt
if [ $DNSSERVER == 'bind' ]; then
        mv $BASE/$FOLDER_BL/master.list.zones $BASE/$FOLDER_BL/backup/master.list.zones.$today.txt
elif [ $DNSSERVER == 'unbound' ]; then
        mv $BASE/$FOLDER_BL/blacklisted_domains.conf $BASE/$FOLDER_BL/backup/blacklisted_domains.conf.$today.txt
fi



##############################################
#########  malwaredomains.com   ##############	
##############################################
	if [ $SAGADC -ne 0 ]; then
		wget http://dns-bh.sagadc.org/domains.txt -O $BASE/$FOLDER_BL/dns-bh.sagadc.org.tmp
		more $BASE/$FOLDER_BL/dns-bh.sagadc.org.tmp | grep -v '#' | awk '{print $2}' \
			| cut -d'?' -f1 >> $BASE/$FOLDER_BL/master.list
		if [ $DELETE == 1 ]; then rm -rf $BASE/$FOLDER_BL/dns-bh.sagadc.org.tmp ; fi
	fi

##################################################
#########  spyeyetracker.abuse.ch   ##############
##################################################
	if [ $SPYEYE -ne 0 ]; then
		wget --no-check-certificate -t 3 https://spyeyetracker.abuse.ch/blocklist.php?download=domainblocklist -O $BASE/$FOLDER_BL/spyeyetracker.tmp
		cat $BASE/$FOLDER_BL/spyeyetracker.tmp | grep -v '#' | cut -d'?' -f1 >> $BASE/$FOLDER_BL/master.list
		if [ $DELETE == 1 ]; then rm -rf $BASE/$FOLDER_BL/spyeyetracker.tmp ; fi
	fi
##############################################
##############  zeustracker   ################
##############################################
	if [ $ZEUSTRACKER -ne 0 ]; then
		wget -t 3 http://www.abuse.ch/zeustracker/blocklist.php?download=domainblocklist -O $BASE/$FOLDER_BL/zeustracker.tmp
		cat $BASE/$FOLDER_BL/zeustracker.tmp | grep -v '#' | cut -d'?' -f1 >> $BASE/$FOLDER_BL/master.list
		if [ $DELETE == 1 ]; then rm -rf $BASE/$FOLDER_BL/zeustracker.tmp ; fi
	fi
	
##############################################
##############  palevotracker   ################
##############################################
	if [ $PALEVOTRACKER -ne 0 ]; then
		wget --no-check-certificate -t 3 https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist -O palevotracker.tmp
		cat $BASE/$FOLDER_BL/palevotracker.tmp | grep -v '#' | cut -d'?' -f1 >> $BASE/$FOLDER_BL/master.list
		if [ $DELETE == 1 ]; then rm -rf $BASE/$FOLDER_BL/palevotracker.tmp ; fi
	fi

#######################################################################
# Download from ISC High list Most Observed Malware-Related DNS Names #
#######################################################################
	if [ $ISCSANS -ne 0 ]; then
		#wget -t 3 http://isc.sans.edu/feeds/suspiciousdomains_Low.txt -O $BASE/$FOLDER_BL/suspiciousdomains_Low.txt
		wget -t 3 http://isc.sans.edu/feeds/suspiciousdomains_Medium.txt -O $BASE/$FOLDER_BL/suspiciousdomains_Medium.tmp
		wget -t 3 http://isc.sans.edu/feeds/suspiciousdomains_High.txt -O $BASE/$FOLDER_BL/suspiciousdomains_High.tmp

		#cat $BASE/$FOLDER_BL/suspiciousdomains_Low.txt | grep -v ^# | grep -v ^Site | sed '/^$/d' > $BASE/$FOLDER_BL/ISC.txt
		cat $BASE/$FOLDER_BL/suspiciousdomains_Medium.tmp | grep -v ^# | grep -v ^Site | sed '/^$/d' >> $BASE/$FOLDER_BL/ISC.tmp
		cat $BASE/$FOLDER_BL/suspiciousdomains_High.tmp | grep -v ^# | grep -v ^Site | sed '/^$/d' >> $BASE/$FOLDER_BL/ISC.tmp

		cat $BASE/$FOLDER_BL/ISC.tmp | grep -v "[[:digit:]]\{1,3\}\.[[:digit:]]\{1,3\}\.[[:digit:]]\{1,3\}\.[[:digit:]]\{1,3\}" \
			| sort | uniq | cut -d'?' -f1 >> $BASE/$FOLDER_BL/isc2.tmp
		cat $BASE/$FOLDER_BL/isc.tmp >> $BASE/$FOLDER_BL/master.list
		if [ $DELETE == 1 ]; then
			rm -rf $BASE/$FOLDER_BL/suspiciousdomains_Low.tmp  $BASE/$FOLDER_BL/suspiciousdomains_Medium.tmp
			rm -rf $BASE/$FOLDER_BL/suspiciousdomains_High.tmp $BASE/$FOLDER_BL/ISC.tmp $BASE/$FOLDER_BL/isc2.tmp
		fi
	fi
	
	
#################################
## Malcode
#################################
	if [ $MALCODE -ne 0 ]; then
		wget -t 3 http://malc0de.com/bl/ZONES -O $BASE/$FOLDER_BL/malcode.tmp
		more $BASE/$FOLDER_BL/malcode.tmp | cut -d'"' -f2 | grep -v -E "//|^$|#" \
			| cut -d'?' -f1 >> $BASE/$FOLDER_BL/master.list
		if [ $DELETE == 1 ]; then rm -rf $BASE/$FOLDER_BL/malcode.tmp ; fi
	fi

#################################
## Sucuri
#################################
	if [ $SUCURI -ne 0 ]; then
		wget -t 3 http://labs.sucuri.net/?malware -O $BASE/$FOLDER_BL/index_sucuri.tmp
		more $BASE/$FOLDER_BL/index_sucuri.tmp | sed 's/iframe/\n\r/g; s/redirections/\n\r/g; s/javascript/\n\r/g'| awk '{ print $3 }' \
			| tr = " " | tr \" " " | awk '{ print $3 }' | sed '/td><td/d; /^$/d' \
			| grep -v -E "><|>|<" | cut -d'?' -f1 >> $BASE/$FOLDER_BL/sucuri.tmp
		cat $BASE/$FOLDER_BL/sucuri.tmp >> $BASE/$FOLDER_BL/master.list
		if [ $DELETE == 1 ]; then rm -rf $BASE/$FOLDER_BL/sucuri.tmp $BASE/$FOLDER_BL/index_sucuri.tmp ; fi
	fi

#################################
## Malware blacklist
#################################
	if [ $MALWAREBLACKLIST -ne 0 ]; then
		wget -t 3 www.malwareblacklist.com/mbl.xml -O $BASE/$FOLDER_BL/malwareblacklist.xml.tmp
		cat malwareblacklist.xml.tmp | grep Host: | sed 's/http://g' | tr \/ " " | awk '{ print $2 }' | sort | uniq \
			| grep -v "[[:digit:]]\{1,3\}\.[[:digit:]]\{1,3\}\.[[:digit:]]\{1,3\}\.[[:digit:]]\{1,3\}" \
			| sed 's/\:[0-9 ].*//' | cut -d'?' -f1 >> $BASE/$FOLDER_BL/malwareblacklist.tmp
		cat $BASE/$FOLDER_BL/malwareblacklist.tmp >> $BASE/$FOLDER_BL/master.list
		if [ $DELETE == 1 ]; then rm -rf $BASE/$FOLDER_BL/malwareblacklist.xml.tmp $BASE/$FOLDER_BL/malwareblacklist.tmp ; fi
	fi

##################################################################################
# http://www.malwarepatrol.net
##################################################################################
	# Download Malware Patrol list Most Observed Malware-Related DNS Names
	if [ $MALWAREPATROL -ne 0 ]; then
		wget -t 3 http://www.malwarepatrol.net/cgi/submit?action=list_bind -O $BASE/$FOLDER_BL/malwarepatrol.tmp
		cat $BASE/$FOLDER_BL/malwarepatrol.tmp | awk '{ print $2 }' | sed 's/\"//g' \
			| sed '/^$/d' | cut -d'?' -f1 >> $BASE/$FOLDER_BL/malwarepatrol2.tmp

		cat $BASE/$FOLDER_BL/malwarepatrol2.tmp >> $BASE/$FOLDER_BL/master.list
		if [ $DELETE == 1 ]; then rm -rf $BASE/$FOLDER_BL/malwarepatrol.tmp $BASE/$FOLDER_BL/malwarepatrol2.tmp ; fi
	fi

##################################################################################
# http://mtc.sri.com/live_data/malware_dns/
# Download a list of the most observed malware DNS names that we have seen looked
# up during malware infections or embedded within malware binaries.
##################################################################################
   # Download SRI Malware Threat Center
	if [ $MTC_SRI -ne 0 ]; then
		wget -t 3 http://mtc.sri.com/live_data/malware_dns/ -O $BASE/$FOLDER_BL/sri.com.tmp
		cat $BASE/$FOLDER_BL/sri.com.tmp | grep -A 1 img | grep -E -v "img|--"  \
			| sed 's/<td>//g; s/<\/td>//g;' | cut -d'?' -f1 >> $BASE/$FOLDER_BL/sri.com2.tmp

		cat $BASE/$FOLDER_BL/sri.com.txt >> $BASE/$FOLDER_BL/master.list
		if [ $DELETE == 1 ]; then rm -rf $BASE/$FOLDER_BL/sri.com.tmp $BASE/$FOLDER_BL/sri.com2.tmp ; fi
	fi

  ##################################################################################
  # http://exposure.iseclab.org/about.html
  # EXPOSURE is a service that identifies domain names that are involved in malicious activity  
  # by performing large-scale passive DNS analysis.
  ##################################################################################
	# Download Exposure malicious DNS Names
	if [ $ISECLAB -ne 0 ]; then
		wget -t 3 http://exposure.iseclab.org/malware_domains.txt -O $BASE/$FOLDER_BL/iseclab.org.tmp
		cat $BASE/$FOLDER_BL/iseclab.org.tmp | sed '/^$/d' | cut -d'?' -f1 >> $BASE/$FOLDER_BL/master.list
		if [ $DELETE == 1 ]; then rm -rf $BASE/$FOLDER_BL/iseclab.org.tmp ; fi
	fi

##########################################
#######   support.clean-mx.de/clean-mx
##########################################
	if [ $CLEANMX -ne 0 ]; then
		wget -t 3 'http://support.clean-mx.de/clean-mx/xmlviruses?format=xml&fields=review,url&response=alive' \
			-O $BASE/$FOLDER_BL/clean.mx.txt
		more $BASE/$FOLDER_BL/clean.mx.txt | grep CDATA | cut -d'/' -f3 | cut -d']' -f1 |grep -v ':' \
		 | grep -v "[[:digit:]]\{1,3\}\.[[:digit:]]\{1,3\}\.[[:digit:]]\{1,3\}\.[[:digit:]]\{1,3\}" \
		 | sort | uniq | cut -d'?' -f1 >> $BASE/$FOLDER_BL/master.list
		if [ $DELETE == 1 ]; then rm -rf $BASE/$FOLDER_BL/clean.mx.txt ; fi
	fi
#########################################################
#######   http://www.nictasoft.com/ace/malware-urls/
#########################################################
	if [ $NICTASOFT -ne 0 ]; then
		wget -t 3 http://www.nictasoft.com/ace/malware-urls/ -O $BASE/$FOLDER_BL/nictasoft.tmp
		more $BASE/$FOLDER_BL/nictasoft.tmp | grep -E "href" | grep "td" | cut -d'>' -f4 | cut -d'/' -f3 \
			| cut -d'?' -f1 | grep -v -E "\.\.\.|nictasoft" | cut -d'<' -f 1 | cut -d':' -f1 \
			| sort | uniq >> $BASE/$FOLDER_BL/master.list
		if [ $DELETE == 1 ]; then rm -rf $BASE/$FOLDER_BL/nictasoft.tmp ; fi
	fi
#########################################################
#######   http://mirror1.malwaredomains.com/files/spywaredomains.zones
#########################################################
	if [ $MALWAREDOMAINS_SPY -ne 0 ]; then
		wget -t 3 "http://mirror1.malwaredomains.com/files/spywaredomains.zones" -O $BASE/$FOLDER_BL/malwaredomains_spy.tmp
		cat $BASE/$FOLDER_BL/malwaredomains_spy.tmp | cut -d'"' -f2 | cut -d'"' -f1 | grep -v '//' | sort \
		 | uniq >> $BASE/$FOLDER_BL/master.list
		if [ $DELETE == 1 ]; then rm -rf $BASE/$FOLDER_BL/malwaredomains_spy.tmp ; fi
	fi


## refining records.. remove rubbish.. files are the same..
cat $BASE/$FOLDER_BL/master.list | grep -v '<' | grep -v '>' | grep -v '#' | grep -v '//' \
	| sed '/^$/d' | grep -v -E "\.$" > $BASE/$FOLDER_BL/master.list.tmp
rm -rf $BASE/$FOLDER_BL/master.list
mv $BASE/$FOLDER_BL/master.list.tmp $BASE/$FOLDER_BL/master.list

cat $BASE/$FOLDER_BL/tmp.blacklist  >> $BASE/$FOLDER_BL/master.list


##
## Outputting. Either in BIND format or UNBOUND format
##
if [ $DNSSERVER == "bind" ]; then
	rm -rf $BASE/$FOLDER_BL/master.list.zones
	for a in `cat $BASE/$FOLDER_BL/master.list | grep -v '#'`;  do 
		echo "zone \"$a\" {type master; file \"/etc/bind/master.list.hosts\";};" >> $BASE/$FOLDER_BL/master.list.zones
	done
	echo "Configuration file generated : $BASE/$FOLDER_BL/master.list.zones"
elif [ $DNSSERVER == 'unbound' ]; then
	rm -rf $BASE/$FOLDER_BL/blacklisted_domains.conf
	for a in `cat $BASE/$FOLDER_BL/master.list | grep -v '#'`; do
		echo 'local-data: "'$a' A 172.16.40.226"' >> $BASE/$FOLDER_BL/blacklisted_domains.conf
	done
	echo "Configuration file generated : $BASE/$FOLDER_BL/blacklisted_domains.conf"
fi


$BASE/$FOLDER_BL/whitelist_checker.sh
