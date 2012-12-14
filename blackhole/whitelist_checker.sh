#!/bin/bash

dns_config_file="blacklisted_domains.conf"


if [ ! -f tmp.whitelist ]; then
        touch tmp.whitelist
fi

for a in `cat tmp.whitelist`; do
        sed -i '/'$a'/d' $dns_config_file
done

