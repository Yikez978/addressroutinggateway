#!/bin/bash
# Give it just a sencond to ensure Dropbox knows it needs to start syncing
sleep .5

while [[ `dropbox status | grep Idle` == "" ]]
do
	echo Waiting for Dropbox to finish syncing...
	sleep 1
done

echo Dropbox is synced!
