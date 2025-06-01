#!/bin/bash
set -e

# Usage: cloudstack_mgmt_start.sh stop|0:1
STOP=$1
MAX_DURATION=300
DELAY=10

if [ "$STOP" = "1" ] ; then
  # Make sure mariadb is stopped
  systemctl stop cloudstack-management
  sleep 5
fi

# Start it
cloudstack-setup-management

start=`date +%s`
sleep ${DELAY}
while ! nc -q 0 -v localhost 8080 < /dev/null > /dev/null 2>&1 ; do
  if ! systemctl is-active cloudstack-management > /dev/null 2>&1 ; then
    echo "Cloudstack Management unexpectedly quit"
    exit 1
  fi
  curr=`date +%s`
  let "duration = curr - start"
  if [ $duration -gt $MAX_DURATION ] ; then
    echo "Took too long to start"
    exit 1
  fi
  sleep ${DELAY}
done

sleep ${DELAY}

exit 0
