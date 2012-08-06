#!/bin/bash
# Runs the given script on all given IPs.
# Must have private key login available 
# Reports any problems at end
# Machine categories
GATEWAYS="172.100.0.10 172.100.0.11"
CLIENTS="172.100.0.20 172.100.0.21"
SERVERS=

# Who to actually run on
if [ a"$1" == a"-t" ]
then
	# Use just the target specified
	SYSTEMS="$2"
	shift
	shift
else
	# Use default targets
	SYSTEMS="$GATEWAYS $CLIENTS $SERVERS"
fi

# Save off the script name we will actually run
if [ ! -e "$1" ]
then
	echo A script must be given as the first argument
	exit 1
fi

SCRIPT_NAME=`basename $1`

errors=()
for s in $SYSTEMS
do
	# Push all files to target
	echo Pushing files to $s
	if ! scp -r "$@" "$s:"
	then
		# Failed to push. Try next server
		errors+=("Pushing to $s")
		continue
	fi
	
	# Run the first thing we pushed
	echo Running "$SCRIPT_NAME" on $s
	if ! ssh $s "~/$SCRIPT_NAME"
	then
		errors+=("Running on $s")
	fi
done

if [ "${#errors[*]}" != 0 ]
then
	echo The following errors were encountered:
	for e in "${errors[@]}"
	do
		echo -e "\t$e"
	done
	
	exit 2
fi

