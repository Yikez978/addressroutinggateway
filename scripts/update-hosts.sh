#!/bin/bash
# Ensure we're at the base of the src tree
cd `dirname $_`
cd ..

# And install hosts file
scripts/run-on-all.sh scripts/helper/update_hosts_file.sh /etc/hosts

