#!/bin/bash

set -e
. /usr/bin/arcore_lib.sh
mkdir -p "/etc/systemd/network"

COUNTER=0
for_each_cmdline() {
    case $1 in
        arcore.net)
            echo "$2" | sed -e 's/\\n/\n/g' > /etc/systemd/network/$COUNTER-default$COUNTER.network
	    COUNTER=$((COUNTER+1))
            ;;
        *)
            # ignore other cmdline
            ;;
    esac
}

parse_cmdline for_each_cmdline
