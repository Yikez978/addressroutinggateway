#!/bin/bash
# Ensure we're at the base of the src tree
cd `dirname $_`
cd ..

# Kill off ARG if it's currently running
echo Ensuring ARG is not running
scripts/stop-arg-servers.sh

# Start ARG
scripts/run-on-all.sh scripts/helper/start-gateway.sh arg

