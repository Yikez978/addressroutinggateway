#!/bin/bash
# Ensure we're at the base of the src tree
cd `dirname $_`
cd ..

echo Stopping ARG
scripts/run-on-all.sh scripts/helper/stop-gateway.sh 

