#!/bin/bash
today=`date "+%Y-%m-%d-%H-%M-%S"`

BASE="/etc/unbound"
FOLDER_BL="blackhole"

#### Notes
###	http://www.digriz.org.uk/network-layer-protection/dns
###

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
CLEANMX=1

## Choose which DNS server are you using, BIND of UNBOUND
DNSSERVER="unbound" # bind or unbound

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
		rm -rf $BASE/$FOLDER_BL/dns-bh.sagadc.org.txt
		wget http://dns-bh.sagadc.org/domains.txt -O $BASE/$FOLDER_BL/dns-bh.sagadc.org.txt
		more $BASE/$FOLDER_BL/dns-bh.sagadc.org.txt | grep -v '#' | awk '{print $2}' >> $BASE/$FOLDER_BL/master.list
		rm -rf $BASE/$FOLDER_BL/dns-bh.sagadc.org.txt
	fi

##################################################
#########  spyeyetracker.abuse.ch   ##############
##################################################
	if [ $SPYEYE -ne 0 ]; then
		wget --no-check-certificate -t 3 https://spyeyetracker.abuse.ch/blocklist.php?download=domainblocklist -O $BASE/$FOLDER_BL/spyeyetracker.txt
		cat $BASE/$FOLDER_BL/spyeyetracker.txt | grep -v '#' >> $BASE/$FOLDER_BL/master.list
		rm -rf $BASE/$FOLDER_BL/spyeyetracker.txt
	fi
##############################################
##############  zeustracker   ################
##############################################
	if [ $ZEUSTRACKER -ne 0 ]; then
		wget -t 3 http://www.abuse.ch/zeustracker/blocklist.php?download=domainblocklist -O $BASE/$FOLDER_BL/zeustracker.txt
		cat $BASE/$FOLDER_BL/zeustracker.txt | grep -v '#' >> $BASE/$FOLDER_BL/master.list
		rm -rf $BASE/$FOLDER_BL/zeustracker.txt
	fi
	
##############################################
##############  palevotracker   ################
##############################################
	if [ $PALEVOTRACKER -ne 0 ]; then
		wget --no-check-certificate -t 3 https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist -O palevotracker.tmp
		cat $BASE/$FOLDER_BL/palevotracker.tmp | grep -v '#' >> $BASE/$FOLDER_BL/master.list
		rm -rf $BASE/$FOLDER_BL/palevotracker.tmp
	fi

#######################################################################
# Download from ISC High list Most Observed Malware-Related DNS Names #
#######################################################################
	if [ $ISCSANS -ne 0 ]; then
		wget -t 3 http://isc.sans.edu/feeds/suspiciousdomains_Low.txt -O $BASE/$FOLDER_BL/suspiciousdomains_Low.txt
		wget -t 3 http://isc.sans.edu/feeds/suspiciousdomains_Medium.txt -O $BASE/$FOLDER_BL/suspiciousdomains_Medium.txt
		wget -t 3 http://isc.sans.edu/feeds/suspiciousdomains_High.txt -O $BASE/$FOLDER_BL/suspiciousdomains_High.txt

		cat $BASE/$FOLDER_BL/suspiciousdomains_Low.txt | grep -v ^# | grep -v ^Site | sed '/^$/d' > $BASE/$FOLDER_BL/ISC.txt
		cat $BASE/$FOLDER_BL/suspiciousdomains_Medium.txt | grep -v ^# | grep -v ^Site | sed '/^$/d' >> $BASE/$FOLDER_BL/ISC.txt
		cat $BASE/$FOLDER_BL/suspiciousdomains_High.txt | grep -v ^# | grep -v ^Site | sed '/^$/d' >> $BASE/$FOLDER_BL/ISC.txt

		cat $BASE/$FOLDER_BL/ISC.txt | grep -v "[[:digit:]]\{1,3\}\.[[:digit:]]\{1,3\}\.[[:digit:]]\{1,3\}\.[[:digit:]]\{1,3\}" | sort | uniq >> $BASE/$FOLDER_BL/isc.tmp
		cat $BASE/$FOLDER_BL/isc.tmp >> $BASE/$FOLDER_BL/master.list
		rm -rf $BASE/$FOLDER_BL/suspiciousdomains_Low.txt  $BASE/$FOLDER_BL/suspiciousdomains_Medium.txt $BASE/$FOLDER_BL/suspiciousdomains_High.txt $BASE/$FOLDER_BL/ISC.txt $BASE/$FOLDER_BL/isc.tmp
	fi
	
	
#################################
## Malcode
#################################
	if [ $MALCODE -ne 0 ]; then
		wget -t 3 http://malc0de.com/bl/ZONES -O $BASE/$FOLDER_BL/malcode.txt
		more $BASE/$FOLDER_BL/malcode.txt | cut -d'"' -f2 | grep -v -E "//|^$|#" >> $BASE/$FOLDER_BL/master.list
		rm -rf $BASE/$FOLDER_BL/malcode.txt
	fi

#################################
## Sucuri
#################################
	if [ $SUCURI -ne 0 ]; then
		wget -t 3 http://labs.sucuri.net/?malware -O $BASE/$FOLDER_BL/index_sucuri.html
		more $BASE/$FOLDER_BL/index_sucuri.html | sed 's/iframe/\n\r/g; s/redirections/\n\r/g; s/javascript/\n\r/g'| awk '{ print $3 }' \
			| tr = " " | tr \" " " | awk '{ print $3 }' | sed '/td><td/d; /^$/d' | grep -v -E "><|>|<" >> $BASE/$FOLDER_BL/sucuri.txt
		cat $BASE/$FOLDER_BL/sucuri.txt >> $BASE/$FOLDER_BL/master.list
		rm -rf $BASE/$FOLDER_BL/sucuri.txt $BASE/$FOLDER_BL/index_sucuri.html
	fi

#################################
## Malware blacklist
#################################
	if [ $MALWAREBLACKLIST -ne 0 ]; then
		wget -t 3 www.malwareblacklist.com/mbl.xml -O $BASE/$FOLDER_BL/mbl.xml
		cat mbl.xml | grep Host: | sed 's/http://g' | tr \/ " " | awk '{ print $2 }' | sort | uniq \
			| grep -v "[[:digit:]]\{1,3\}\.[[:digit:]]\{1,3\}\.[[:digit:]]\{1,3\}\.[[:digit:]]\{1,3\}" \
			| sed 's/\:[0-9 ].*//' >> $BASE/$FOLDER_BL/malwareblacklist.txt
		cat $BASE/$FOLDER_BL/malwareblacklist.txt >> $BASE/$FOLDER_BL/master.list
		rm -rf $BASE/$FOLDER_BL/mbl.xml $BASE/$FOLDER_BL/malwareblacklist.txt
	fi

##################################################################################
# http://www.malwarepatrol.net
##################################################################################
	# Download Malware Patrol list Most Observed Malware-Related DNS Names
	if [ $MALWAREPATROL -ne 0 ]; then
		wget -t 3 http://www.malwarepatrol.net/cgi/submit?action=list_bind -O $BASE/$FOLDER_BL/malwarepatrol.tmp
		cat $BASE/$FOLDER_BL/malwarepatrol.tmp | awk '{ print $2 }' | sed 's/\"//g' | sed '/^$/d' >> $BASE/$FOLDER_BL/malwarepatrol.txt

		cat $BASE/$FOLDER_BL/malwarepatrol.txt >> $BASE/$FOLDER_BL/master.list
		rm -rf $BASE/$FOLDER_BL/malwarepatrol.txt $BASE/$FOLDER_BL/malwarepatrol.tmp
	fi

##################################################################################
# http://mtc.sri.com/live_data/malware_dns/
# Download a list of the most observed malware DNS names that we have seen looked
# up during malware infections or embedded within malware binaries.
##################################################################################
   # Download SRI Malware Threat Center
	if [ $MTC_SRI -ne 0 ]; then
		wget -t 3 http://mtc.sri.com/live_data/malware_dns/ -O $BASE/$FOLDER_BL/sri.com.tmp
		cat $BASE/$FOLDER_BL/sri.com.tmp | grep -A 1 img | grep -E -v "img|--"  | sed 's/<td>//g; s/<\/td>//g;' >> $BASE/$FOLDER_BL/sri.com.txt

		cat $BASE/$FOLDER_BL/sri.com.txt >> $BASE/$FOLDER_BL/master.list
		rm -rf $BASE/$FOLDER_BL/sri.com.tmp $BASE/$FOLDER_BL/sri.com.txt
	fi

  ##################################################################################
  # http://exposure.iseclab.org/about.html
  # EXPOSURE is a service that identifies domain names that are involved in malicious activity  
  # by performing large-scale passive DNS analysis.
  ##################################################################################
	# Download Exposure malicious DNS Names
	if [ $ISECLAB -ne 0 ]; then
		wget -t 3 http://exposure.iseclab.org/malware_domains.txt -O $BASE/$FOLDER_BL/iseclab.org.txt
		cat $BASE/$FOLDER_BL/iseclab.org.txt | sed '/^$/d' >> $BASE/$FOLDER_BL/master.list
		rm -rf $BASE/$FOLDER_BL/iseclab.org.txt
	fi

##########################################
#######   support.clean-mx.de/clean-mx
##########################################
	if [ $CLEANMX -ne 0 ]; then
		wget -t 3 'http://support.clean-mx.de/clean-mx/xmlviruses?format=xml&fields=review,url&response=alive' \
			-O $BASE/$FOLDER_BL/clean.mx.txt
		more $BASE/$FOLDER_BL/clean.mx.txt | grep CDATA | cut -d'/' -f3 | cut -d']' -f1 |grep -v ':' \
		 | grep -v "[[:digit:]]\{1,3\}\.[[:digit:]]\{1,3\}\.[[:digit:]]\{1,3\}\.[[:digit:]]\{1,3\}" \
		 | sort | uniq >> $BASE/$FOLDER_BL/master.list
		 rm -rf $BASE/$FOLDER_BL/clean.mx.txt
	fi

## refining records.. remove rubbish.. files are the same..
cat $BASE/$FOLDER_BL/master.list | grep -v '<' | grep -v '>' | grep -v '#' | grep -v '//' \
	| sed '/^$/d' | grep -v -E "\.$" > $BASE/$FOLDER_BL/master.list.tmp
rm -rf $BASE/$FOLDER_BL/master.list
mv $BASE/$FOLDER_BL/master.list.tmp $BASE/$FOLDER_BL/master.list

#rm -rf $BASE/$FOLDER_BL/tmpfile.txt
#touch $BASE/$FOLDER_BL/tmpfile.txt
#for b in `cat $BASE/$FOLDER_BL/master.list`; do
#        lines=`grep -i $b $BASE/$FOLDER_BL/tmpfile.txt | wc -l`
#        if [ $lines -eq 0 ]; then
#                echo $b >> $BASE/$FOLDER_BL/tmpfile.txt
#        fi
#done

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
	for a in `cat $BASE/$FOLDER_BL/tmpfile.txt | grep -v '#'`; do
		echo 'local-data: "'$a' A 172.16.40.226"' >> $BASE/$FOLDER_BL/blacklisted_domains.conf
	done
	echo "Configuration file generated : $BASE/$FOLDER_BL/blacklisted_domains.conf"
fi

rm -rf $BASE/$FOLDER_BL/tmpfile.txt