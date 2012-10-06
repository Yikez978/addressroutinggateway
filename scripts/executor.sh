#!/bin/bash
PUSHDIR="~/pushed"
LOCAL="ramlap"
GATES="gateA gateB"
EXT="ext1"
PROT="protA1 protB1"
LATENCY="delay1"

ALL="$GATES $EXT $PROT $DELAY"

SCRIPT=`basename $0`

# Gate control
function start-arg {
	if [[ "$LOCAL" == "$1" ]]
	then
		push-to $GATES - ../arg ../conf/*
		run-on $GATES - start-arg
	else
		[[ "$1" == "gate" ]] || return 0
		sudo ./arg arg.conf `hostname`
	fi
}

function stop-arg {
	if [[ "$LOCAL" == "$1" ]]
	then
		push-to $GATES - ../arg ../conf/*
		run-on $GATES - start-arg
	else
		# Send it kill signal
		echo Sending signal
		sudo killall -INT arg

		# Wait for up to 5 seconds for it to stop
		for i in {1..10}
		do
			# Check for the process
			if [[ `ps -A | grep arg` == "" ]]
			then
				return 0
			fi
			
			# Wait
			echo Waiting for ARG to die
			sleep .5
		done

		# Force it to die
		sudo killall -KILL arg
		return 0
	fi
}

# Network setup changes
function set-latency {
	if [[ "$LOCAL" == "$1" ]]
	then
		push-to $LATENCY - 
		run-on $LATENCY - set-latency
	else
		[[ "$1" == "delay" ]] || return 0

		if [ "$#" == "1" ]
		then
			toExt=$1
			toA=$1
			toB=$1
		elif [ "$#" == "2" ]
		then
			toExt=$2
			toA=$1
			toB=$1
		elif [ "$#" == "3" ]
		then
			toExt=$3
			toA=$1
			toB=$2
		else
			echo 'Usage: set-latency <gate a> <gate b> <ext>'
			return 1
		fi

		# Main bridge ("internet")
		sudo tc qdisc replace dev eth1 root netem delay "$toExt"
		sudo tc qdisc replace dev eth2 root netem delay "$toA"
		sudo tc qdisc replace dev eth3 root netem delay "$toB"

		return 0
	fi
}

# The basics
function reboot {
	if [[ "$LOCAL" == "$1" ]]
	then
		push-to $ALL -
		run-on $ALL - reboot
	else
		sudo shutdown -r 1
	fi
}

function shutdown {
	if [[ "$LOCAL" == "$1" ]]
	then
		push-to $ALL -
		run-on $ALL - shutdown
	else
		sudo shutdown -h 1
	fi
}

function enable-forwarding {
	if [[ "$LOCAL" == "$1" ]]
	then
		push-to $GATES -
		run-on $GATES - enable-forwarding
	else
		[[ "$1" == "gate" ]] || return 0
		echo 1 > /proc/sys/net/ipv4/ip_forward
	fi
}

function disable-forwarding {
	if [[ "$LOCAL" == "$1" ]]
	then
		push-to $GATES -
		run-on $GATES - enable-forwarding
	else
		[[ "$1" == "gate" ]] || return 0
		echo 0 > /proc/sys/net/ipv4/ip_forward
	fi
}

function install-vmware-tools {
	if [[ "$LOCAL" == "$1" ]]
	then
		push-to $ALL -  
		run-on $ALL - install-vmware-tools
	else
		# Mount CD and pull off tools
		sudo mount /dev/cdrom /media/cdrom
		cp /media/cdrom/VMware*.tar.gz ~
		tar -xzf VMware*.tar.gz

		# Install tools
		cd vmware*
		sudo ./vmware-install.pl --default

		# Clean up slightly
		sudo umount /media/cdrom
		rm -r VMware*.tar.gz
		sudo shutdown -r 1 &	
	fi
}

# Helpers for getting needed stuff to test network
function push-to {
	# Get the list of servers to run on. Lists ends with '-'
	systems=""
	while (( "$#" ))
	do
		if [[ "$1" == "-" ]]
		then
			shift
			break
		fi

		systems="$systems $1"
		shift
	done

	if [[ "$systems" == "" ]]
	then
		echo No systems supplied
		return 1
	fi

	# And now push files
	files="SCRIPT" "$@"

	echo Pushing to...
	for s in $systems
	do
		echo -e "\t$s"
		if ! scp -r "$files" "$s:$PUSHDIR"
		then
			echo Unable to push to $s:$PUSHDIR
			continue
		fi
	done

	return 0
}

function run-on {
	# Get the list of servers to run on. Lists ends with '-'
	systems=""
	while (( "$#" ))
	do
		if [[ "$1" == "-" ]]
		then
			shift
			break
		fi

		systems="$systems $1"
		shift
	done

	if [[ "$systems" == "" ]]
	then
		echo No systems supplied
		return 1
	fi

	# Run the requested function
	if [[ "$#" != "1" ]]
	then
		echo No function given to call $# $@
		return 1
	fi

	echo Running on...
	for s in $systems
	do
		echo -e "\t$s"
		if ! ssh "$s" "$PUSHDIR/$SCRIPT" $1
		then
			echo Unable to run $s:$PUSHDIR
		fi
	done

	return 0
}

function clean-pushed {
	if [[ "$LOCAL" == "$1" ]]
	then
		push-to $ALL -  
		run-on $ALL - clean-pushed
	else
		rm -rif *
	fi
}

# Main controller
function main {
	if [[ "$#" == "0" ]]
	then
		echo Usage: $0 \<function\>
		return 1
	fi

	# Determine what type of host we are
	TYPE=`hostname | sed -E 's/([[:lower:]]+).*/\1/g'`
	echo Running as a $TYPE
	
	# Move into the directory with this script so we have 
	# a frame of reference for paths
	cd `dirname "${BASH_SOURCE[0]}"`

	# Call actual functionality
	func=$1
	shift
	echo Executing helper script $func
	"$func" "$TYPE" "$@"
}
main "$@"

