#!/bin/bash
PUSHDIR="~/pushed"

LOCAL="ramlap"
IS_LOCAL=1

GATES="gateA gateB"
EXT="ext1"
PROT="protA1 protB1"
LATENCY="delay1"

ALL="$GATES $EXT $PROT $DELAY"

SCRIPT=`basename $0`

# Tests
function start-tests {
	if [[ $IS_LOCAL ]]
	then
		start-arg

		run-on $PROT - ping 172.100.0.1 '&'
	else
		echo This should only be run from local
	fi
	return 0
}

# Building
# Run-make does a full build on _all_ gates and saves the binary to ~
# Intended for setting up tests, ssh into the gateway should be used for development
# Usage: run-make
function run-make {
	if [[ $IS_LOCAL ]]
	then
		push-to $GATES - ../*
		run-on $GATES - run-make
	else
		./autogen.sh && make clean && make || return 1
		mv arg ~
		mv conf/* ~
		clean-pushed
	fi
	return 0
}

# Gate control
# Builds ARG from scratch and runs it on all gateways
# Usage: start-arg
function start-arg {
	if [[ $IS_LOCAL ]]
	then
		run-make
		run-on $GATES - start-arg
	else
		[[ "$1" == "gate" ]] || return 0
		cd ..
		sudo ./arg arg.conf `hostname` 
	fi
	return 0
}

# Stops ARG on all gateways, first gracefully then forcefully
# Usage: stop-arg
function stop-arg {
	if [[ $IS_LOCAL ]]
	then
		push-to $GATES
		run-on $GATES - stop-arg
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
	fi
	return 0
}

# Network setup changes
# Changes the latency on the delay box to the given value. 
# Latency values are given with their units, e.g., 30ms, 1s, etc
# Usage: set-latency <delay to all>
#        set-latency <delay to gates> <delay to external>
#        set-latency <delay to gate A> <delay to B> <delay to ext>
function set-latency {
	if [[ $IS_LOCAL ]]
	then
		push-to $LATENCY - 
		run-on $LATENCY - set-latency "$2"
	else
		[[ "$1" == "delay" ]] || return 0

		if [ "$#" == "2" ]
		then
			toExt=$2
			toA=$2
			toB=$2
		elif [ "$#" == "3" ]
		then
			toExt=$3
			toA=$2
			toB=$2
		elif [ "$#" == "4" ]
		then
			toExt=$4
			toA=$2
			toB=$3
		else
			echo 'Usage: set-latency <gate a> <gate b> <ext>'
			return 1
		fi

		# Main bridge ("internet")
		sudo tc qdisc replace dev eth1 root netem delay "$toExt"
		sudo tc qdisc replace dev eth2 root netem delay "$toA"
		sudo tc qdisc replace dev eth3 root netem delay "$toB"
	fi
	return 0
}

# The basics
# Reboots all servers
# Usage: reboot
function reboot {
	if [[ $IS_LOCAL ]]
	then
		push-to $ALL -
		run-on $ALL - reboot
	else
		sudo reboot
	fi
	return 0
}

# Shuts down all servers
# Usage: shutdown
function shutdown {
	if [[ $IS_LOCAL ]]
	then
		push-to $ALL -
		run-on $ALL - shutdown
	else
		sudo shutdown -h 0
	fi
	return 0
}

# Enables IPv4 forwarding on the gateways
# Usage: enable-forwarding
function enable-forwarding {
	if [[ $IS_LOCAL ]]
	then
		push-to $GATES -
		run-on $GATES - enable-forwarding
	else
		[[ "$1" == "gate" ]] || return 0
		echo 1 > /proc/sys/net/ipv4/ip_forward
	fi
	return 0
}

# Disables IPv4 forwarding on the gateways
# Usage: disable-forwarding
function disable-forwarding {
	if [[ $IS_LOCAL ]]
	then
		push-to $GATES -
		run-on $GATES - enable-forwarding
	else
		[[ "$1" == "gate" ]] || return 0
		echo 0 > /proc/sys/net/ipv4/ip_forward
	fi
	return 0
}

# Installs VMware tools on all servers. The CD must already be inserted
# Usage: install-vmware-tools
function install-vmware-tools {
	if [[ $IS_LOCAL ]]
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
	return 0
}

# Runs the given command line on all servers. Any command may be used, arguments are allowed
# Usage: run <cmd>
function run {
	if [[ $IS_LOCAL ]]
	then
		push-to $ALL -  
		shift
		run-on $ALL - run "$@"
	else
		shift
		$@
	fi
	return 0
}

# Helpers for getting needed stuff to test network
# Pushes the given files and this script to the given servers
# Usage: push-to <server> [<server> ...] [- <file> ...]
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
	files="$SCRIPT $@"

	echo Pushing to...
	for s in $systems
	do
		echo -e "\t$s"
		if ! scp -r $files "$s:$PUSHDIR"
		then
			echo Unable to push to $s:$PUSHDIR
			continue
		fi
	done

	return 0
}

# Runs the given function on the servers given
# Usage: run-on <server> [<server> ...] - <function>
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
	if [[ "$#" == "0" ]]
	then
		echo No function given to call $@
		return 1
	fi

	echo Running on...
	for s in $systems
	do
		echo -e "\t$s"
		if ! ssh "$s" "$PUSHDIR/$SCRIPT" $@
		then
			echo Unable to run $s:$PUSHDIR
		fi
	done

	return 0
}

# Removes all files in the 'pushed' directory on every server
# Usage: clean-pushed
function clean-pushed {
	if [[ $IS_LOCAL ]]
	then
		push-to $ALL -  
		run-on $ALL - clean-pushed
	else
		rm -rf *
	fi
	return 0
}

# Gives hints on the commands
# Usage: help [<function>]
function help {
	if [[ "$#" == "1" ]]
	then
		echo Usage: $0 \<function\>
		echo Functions available:
		grep '^function' "$0" | grep -v 'function _' | awk '{print "\t"$2}'
		echo
		echo For details, try \'help '<function>'\'
		help $1 help
	else
		echo Help for $2:
		grep --before-context=5 "^function $2" "$0" | grep '^#' | sed -E 's/^#\s*//g' | awk '{print "\t"$0}'
	fi
	return 0
}

# Main controller
function _main {
	# Move into the directory with this script so we have 
	# a frame of reference for paths
	cd `dirname "${BASH_SOURCE[0]}"`

	# Help?
	if [[ "$#" == "0" ]]
	then
		help local
		return 1
	fi

	# Determine what type of host we are
	TYPE=`hostname | sed -E 's/([[:lower:]]+).*/\1/g'`
	if [[ "$LOCAL" == "$TYPE" ]]
	then
		TYPE="local"
		IS_LOCAL=1
	else
		IS_LOCAL=
	fi
	
	echo Running as $TYPE

	# Call actual functionality
	func=$1
	shift
	echo Executing $func
	"$func" "$TYPE" "$@"
}
_main "$@"

