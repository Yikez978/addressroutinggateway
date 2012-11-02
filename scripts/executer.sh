#!/bin/bash
PUSHDIR="~/pushed"
PULLDIR="pulled"
RESULTSDIR="results"

LOCAL="ramlap"
IS_LOCAL=1

GATES="gateA gateB"
EXT="ext1"
PROT="protA1 protB1"
LATENCY="delay1"

ALL="$GATES $EXT $PROT"

# Begins the tests! Runs for <time> seconds with <delay> latency (see set-latency),
# with ARG hopping every <hop rate> milliseconds.
# Usage: start-tests <time> <delay> <hop rate>
function start-tests {
	if [[ ! $IS_LOCAL ]]
	then
		echo Must be run from local
		return
	fi

	if [[ "$#" != 3 ]]
	then
		echo Not enough arguments given
		help start-tests
		return
	fi

	stop-tests
	clean-pushed
	clean-pulled

	#run-make

	echo Setting latency to $2
	set-latency $2
	
	echo Starting collection
	start-collection

	echo Beginning experiment with hop rate $3
	start-arg $3
	start-generators

	echo Running for $1 seconds
	eraseline="\r                             \r"
	i=$1
	while (( $i ))
	do
		echo -ne "$eraseline$i seconds remaining"
		sleep 1
		i=`expr $i - 1`
	done
	echo -e "${eraseline}Done running tests"

	echo Ending test
	stop-tests

	d="`date +%Y-%m-%d-%H:%M:%S`-l$2-hr$3ms"
	echo Pulling logs into $RESULTSDIR/$d
	retrieve-logs "$d"

	echo Analyze away
}

# Ensures all components of a test are dead (gateways, collectors, etc)
# Usage: stop-tests
function stop-tests {
	stop-generators
	stop-collection
	stop-arg
}

# Starts traffic generators on the network. Intended just for testing.
# Full tests will call start-generator directly
# Usage: start-generators
function start-generators {
	if [[ $IS_LOCAL ]]
	then
		push-to $EXT $PROT - scripts/gen_traffic.py
		run-on $EXT $PROT - start-generators
	else
		# What host are we?
		if [[ "$TYPE" == "ext" ]]
		then
			filename="generator-`hostname`-"

			# One UDP and one TCP listener
			start-generator tcp 2000 
			start-generator udp 3000 
		elif [[ "$TYPE" == "prot" ]] 
		then
			# Listen for traffic
			start-generator udp 5000
			start-generator tcp 6000

			# Talk to the UDP and TCP external hosts
			start-generator tcp 2000 172.100.0.1 .2
			sleep .8
			start-generator udp 3000 172.100.0.1 .3
		fi

		if [[ "$HOST" == "protA1" ]]
		then
			start-generator udp 5000 172.2.0.11 .4
		elif [[ "$HOST" == "protB1" ]]
		then
			start-generator tcp 6000 172.1.0.11 .3
		fi
	fi
}

# Starts a single generator on the current or--if local--given host
# Usage: start-generator [<host>] <type> <port> [<host> <delay>]
#	type - tcp or udp
#	host - If given, generator connects to the given host. If not, generator enters listening mode
#	delay - Listeners always send instantly. Senders send one packet every <delay> seconds (may be decimal)
function start-generator {
	if [[ $IS_LOCAL ]]
	then
		tohost=$1
		push-to $tohost - scripts/gen_traffic.py
		shift
		run-on $tohost - start-generator $@
	else
		if [[ "$#" == 2 ]]
		then
			# Listen
			echo $1 listener created on port $2
			filename="`hostname`-listen-$1:$2.log"
			./gen_traffic.py -l -t "$1" -p "$2" >"$filename" 2>&1 &
			disown $!
		elif [[ "$#" == 4 ]]
		then
			# Send
			echo $1 sender created to $3:$2 with $4 second delay
			filename="`hostname`-send-$1-$3:$2-delay:$4.log"
			./gen_traffic.py -t "$1" -p "$2" -h "$3" -d "$4" >"$filename" 2>&1 &
			disown $!
		else
			help start-generator
		fi
	fi
}

# Stops traffic generators on the network
# Usage: stops-generators
function stop-generators {
	if [[ $IS_LOCAL ]]
	then
		push-to $ALL - 
		run-on $ALL - stop-generators
	else
		_stop-process python
	fi
}

# Starts tcpdump running on all hosts on the test network
# Usage: start-collection
function start-collection {
	if [[ $IS_LOCAL ]]
	then
		push-to $ALL -
		run-on $ALL - start-collection
	else
		# Stop any other currently running dumps
		stop-collection

		if [[ "$TYPE" == "gate" ]]
		then
			# Have two interfaces to capture on for gates
			file1="`hostname`-inner.pcap"
			file2="`hostname`-outer.pcap" 
			echo Starting traffic collection to $file1 and $file2
			
			sudo tcpdump -i eth2 -w "$file1" -n not arp &
			disown $!
			sudo tcpdump -i eth1 -w "$file2" -n not arp &
			disown $!
		else
			# Dump traffic on just the one
			filename="`hostname`.pcap" 
			echo Starting traffic collection to $filename
			sudo tcpdump -i eth1 -w "$filename" -n not arp &
			disown $! 
		fi
		sleep 1
	fi
}

# Stops tcpdumps running on all systems
# Usage: stop-collection
function stop-collection {
	if [[ $IS_LOCAL ]]
	then
		push-to $ALL
		run-on $ALL - stop-collection
	else
		_stop-process tcpdump
	fi
}

# Downloads the logs (pcap, ARG gateway, and traffic generator) to the local system
# Saves to the given directory name within $RESULTSDIR
# Usage: retrieve-logs <dir>
function retrieve-logs {
	if [[ ! $IS_LOCAL ]]
	then
		echo Must be run from local
		return
	fi

	clean-pulled
	pull-from $ALL - '*.pcap'
	pull-from $ALL - '*.log'
	
	mkdir -p "$RESULTSDIR"
	rm -f "$PULLDIR/config.log"
	mv "$PULLDIR" "$RESULTSDIR/$1"

	return
}

# Process all runs in the results director
# Usage: process-runs
function process-runs {
	if [[ ! $IS_LOCAL ]]
	then
		echo Must be run from local
		return
	fi
}

# Process a given run's results
# Usage: process-run [<results dir>]
function process-run {
	cd $1
	./scripts/process_run.py 
}

# Run-make does a full build on _all_ gates and saves the binary to ~
# Intended for setting up tests, ssh into the gateway should be used for development
# Usage: run-make
function run-make {
	if [[ $IS_LOCAL ]]
	then
		push-to gateA - conf *.c *.h autogen.sh configure.ac Makefile.am
		run-on gateA - run-make
		pull-from gateA - arg
		mv "$PULLDIR/arg" .
		clean-pulled 
	else
		stop-arg 
		./autogen.sh && make clean && make || return 1
	fi
	return
}

# Builds ARG from scratch and runs it on all gateways. Hops
# every <hop rate> milliseconds.
# Usage: start-arg <hop rate>
function start-arg {
	if [[ $IS_LOCAL ]]
	then
		stop-arg 

		if [ ! -f arg ]
		then
			echo Rebuilding ARG
			run-make 
		fi

		# Generate config file for each gate
		for g in $GATES
		do
			f="conf/main-$g.conf"
			echo Writing gateway configuration file $f

			echo $g > "$f"
			echo eth2 >> "$f"
			echo eth1 >> "$f"
			echo "$1"ms >> "$f"
		done

		push-to $GATES - arg conf
		run-on $GATES - start-arg $@
	else
		sudo ./arg "conf/main-`hostname`.conf" >"`hostname`-gate-hr$1ms.log" 2>&1 &
		disown $!
	fi
	return
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
		_stop-process arg
	fi
	return
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
		run-on $LATENCY - set-latency "$1"
	else
		[[ "$TYPE" == "delay" ]] || return

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
	fi
	return
}

# The basics
# Reboots all servers
# Usage: reboot
function reboot {
	if [[ $IS_LOCAL ]]
	then
		push-to $ALL $LATENCY -
		run-on $ALL $LATENCY - reboot
	else
		sudo reboot
	fi
	return
}

# Shuts down all servers
# Usage: shutdown
function shutdown {
	if [[ $IS_LOCAL ]]
	then
		push-to $ALL $LATENCY -
		run-on $ALL $LATENCY - shutdown
	else
		sudo shutdown -h 0
	fi
	return
}

# Enables IPv4 forwarding on the gateways
# Usage: enable-forwarding
function enable-forwarding {
	if [[ $IS_LOCAL ]]
	then
		push-to $GATES -
		run-on $GATES - enable-forwarding
	else
		[[ "$TYPE" == "gate" ]] || return
		echo 1 > /proc/sys/net/ipv4/ip_forward
	fi
	return
}

# Disables IPv4 forwarding on the gateways
# Usage: disable-forwarding
function disable-forwarding {
	if [[ $IS_LOCAL ]]
	then
		push-to $GATES -
		run-on $GATES - enable-forwarding
	else
		[[ "$TYPE" == "gate" ]] || return
		echo 0 > /proc/sys/net/ipv4/ip_forward
	fi
	return
}

# Requests the given process stop via SIGINT first, then forces it to die after 5 seconds
# Usage: _stop-process <proc name>
function _stop-process {
	# Interrupt
	echo Sending interrupt signal to $1
	sudo killall -INT "$1"

	# Wait for up to 5 seconds for it to stop
	for i in {1..10}
	do
		# Check for the process
		if [[ `ps -A | grep "$1"` == "" ]]
		then
			return
		fi
		
		# Wait
		echo Waiting for $1 to die
		sleep .5
	done

	# Kill
	echo Sending kill signal to $1
	sudo killall "$1"
	sleep .5
	sudo killall -KILL "$1"
}

# Installs VMware tools on all servers. The CD must already be inserted
# Usage: install-vmware-tools
function install-vmware-tools {
	if [[ $IS_LOCAL ]]
	then
		push-to $ALL $LATENCY -  
		run-on $ALL $LATENCY - install-vmware-tools
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
		
		reboot
	fi
	return
}

# Runs the given command line on all servers. Any command may be used, arguments are allowed
# Usage: run <cmd>
function run {
	if [[ $IS_LOCAL ]]
	then
		push-to $ALL -  
		run-on $ALL - run "$@"
	else
		echo Calling the command: $@
		$@
	fi
	return
}

# Helpers for getting needed stuff to test network
# Pushes the given files and this script to the given servers
# Usage: push-to <server> [<server> ...] [- <file> ...]
function push-to {
	# Get the list of servers to push to. Lists ends with '-'
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
		scp -r $files "$s:$PUSHDIR"
	done

	return
}

# Retrieves the given file(s) from the given systems
# Usage: pull-from <server> [<server> ...] - <file> [<file> ...]
function pull-from {
	# Get the list of servers to pull from. Lists ends with '-'
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

	# And now pull files
	if [[ "$#" == "1" ]]
	then
		files="$@"
	else
		files=""
		for f in $@
		do
			files="$files,$f"
			shift 
		done
		files="\\\\{${files:1}\\\\}"
	fi

	echo Pulling from...
	mkdir -p "$PULLDIR"
	for s in $systems
	do
		echo -e "\t$s"
		# TBD, this is probably not right... need to get multiple files. How?
		if ! scp -r "$s:$PUSHDIR/$files" "$PULLDIR"
		then
			echo Unable to pull from $s:$PUSHDIR
			continue
		fi
	done

	return
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
		ssh "$s" "$PUSHDIR/`basename $SCRIPT`" $@ 2>&1 | grep -v 'closed by remote host'
	done

	return
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
	return
}

# Removes all files in the 'pulled' directory on local system
# Usage: clean-pulled
function clean-pulled {
	if [[ ! $IS_LOCAL ]]
	then
		echo Must be run from local
		return
	fi
	
	rm -rf "$PULLDIR/*"
	return
}

# Adds the helper script and cronjob that allows runcmd-*.sh files
# to be added to ~/pushed and be run by cron. Commands get called
# every 1 minute and are only called _once_
# Usage: add-cmdrun-cron
function add-cmdrun-cron {
	if [[ $IS_LOCAL ]]
	then
		push-to $ALL $LATENCY - runcmd.sh
		run-on $ALL $LATENCY - add-cmdrun-cron
	else
		# Move to correct place
		mv runcmd.sh ~
		chmod +x ~/runcmd.sh

		# Check crontab
		if [[ `crontab -l 2>&1 | grep runcmd` == "" ]]
		then
			echo Put this line into the cron:
			echo '* * * * * ~/runcmd.sh'
			echo Got it? 
			read
		fi
	fi
}

# Gives hints on the commands
# Usage: help [<function>]
function help {
	if [[ "$#" == "0" ]]
	then
		echo Usage: $0 \<function\>
		echo Functions available:
		grep '^function' "$SCRIPT" | grep -v 'function _' | awk '{print "\t"$2}'
		echo
		echo For details, try \'help '<function>'\'
		help help
	else
		echo Help for $1:
		grep --before-context=5 "^function $1 {" "$SCRIPT" | grep '^#' | sed -E 's/^#\s*//g' | awk '{print "\t"$0}'
	fi
	return
}

# Main controller
function _main {
	# Move into the directory with this script so we have 
	# a frame of reference for paths
	SOURCE="${BASH_SOURCE[0]}"
	DIR="$( dirname "$SOURCE" )"
	while [ -h "$SOURCE" ]
	do 
		SOURCE="$(readlink "$SOURCE")"
		[[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
		DIR="$( cd -P "$( dirname "$SOURCE"  )" && pwd )"
	done
	cd -P "$( dirname "$SOURCE" )"

	# Determine what type of host we are
	# For local, we move back up to the parent, giving us nice access to all of the source
	HOST=`hostname`
	TYPE=`hostname | sed -E 's/([[:lower:]]+).*/\1/g'`
	if [[ "$LOCAL" == "$TYPE" ]]
	then
		cd ..
		SCRIPT="scripts/`basename $SOURCE`"
		TYPE="local"
		IS_LOCAL=1
	else
		SCRIPT=`basename $SOURCE`
		IS_LOCAL=
	fi

	# Help?
	if [[ "$#" == "0" ]]
	then
		help
		return 1
	fi
	
	# Call actual functionality
	func=$1
	shift
	echo Executing $func
	"$func" "$@"
	if [[ "$?" == "127" ]]
	then
		echo $func does not appear to exist. Your options are:
		help
	fi

	# For god-only-knows-why, ssh loves to keep us alive with our background (but detached!) processes
	if [[ ! $IS_LOCAL ]]
	then
		#echo Committing patricide...
		kill $PPID
	fi
}
_main "$@"
exit $?

