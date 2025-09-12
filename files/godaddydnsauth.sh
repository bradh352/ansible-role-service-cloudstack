#!/bin/bash
. /etc/letsencrypt/godaddy.ini

#Strip only the top domain to get the zone id
#the domain is passed to this script from the certbot script
#this splits it in to 2 variables one each for the domain and the node
DOMAIN=$(expr match "$CERTBOT_DOMAIN" '.*\.\(.*\..*\)')
ITEM=$(expr match "$CERTBOT_DOMAIN" '\(.*\)\..*\..*')
#Create TXT record
#this is required to verify ownership of the domain by LetsEncrypt
#the content of the TXT record is provided by the Certbot script
#the TTL cannot be lower than 600 for godaddy
#this TXT record will remain as this script does not clean it up
#another script can do that if desired
CREATE_DOMAIN="_acme-challenge.$ITEM"
[[ "${ITEM}" == '*' ]]  && CREATE_DOMAIN="_acme-challenge"
curl -X PATCH "https://api.godaddy.com/v1/domains/${DOMAIN}/records" \
     -H     "Authorization: sso-key ${dns_godaddy_api_token}" \
     -H     "Content-Type: application/json" \
     --data '[{ "type":"TXT", "name":"'"$CREATE_DOMAIN"'", "data":"'"$CERTBOT_VALIDATION"'", "ttl":60}]'
#Sleep to make sure the change has time to propagate over to DNS
sleep 60
