#!/bin/bash
# Stops the gateway on the current machine
# Ensure that we actually are a gateway.
[[ -f ~/.gateway ]] || exit 0

# Send it kill signal
echo Sending signal
sudo rmmod arg

# Wait for up to 5 seconds for it to stop
#for i in {1..10}
#do
	# Check for the process
#	if [[ `ps -A | grep arg` == "" ]]
#	then
#		break
#	fi
	
	# Wait
#	echo Waiting for ARG to die
#	sleep .5
#done

