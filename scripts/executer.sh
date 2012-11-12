#!/bin/bash
PUSHDIR="~/pushed"
PULLDIR="pulled"
RESULTSDIR="results"
RUNDB="run.db"
PROCESSLOG="processing.log"

LOCAL="ramlap"
IS_LOCAL=1

GATES="gateA gateB gateC"
EXT="ext1"
PROT="protA1 protB1 protC1"
#LATENCY="delay1"
LATENCY=

ALL="$GATES $EXT $PROT"

# Starts the given test number 
# Usage: start-tests [<time>]
function start-tests {
	if [[ ! $IS_LOCAL ]]
	then
		echo Must be run from local
		return
	fi

	runtime=900
	if [[ "$#" == 1 ]]
	then
		runtime=$1
	fi

	# Ensure we have the newest build
	if ! run-make
	then
		echo Fix build problems before continuing
		return
	fi

	# Do every combination of hop rate (hr), latency, and test
	# First one is no hopping as a consequence of the hop taking the full test length
	for repetition in {1..5}
	do
		for hr in $(($runtime * 1000)) 1000 500 100 50 30 20 10 5 
		do
			for latency in 0
			do
				for testnum in 0 1
				do
					start-test $testnum $runtime $latency $hr 
				done
			done
		done
	done
}

# Begins the tests! Runs test <test num> (see start-generators) for <time> seconds
# with <delay> latency (see set-latency), with ARG hopping every <hop rate> milliseconds.
# Usage: start-test <test num> <time> <latency> <hop rate>
function start-test {
	if [[ ! $IS_LOCAL ]]
	then
		echo Must be run from local
		return
	fi

	if [[ "$#" != 4 ]]
	then
		echo Incorrect number of arguments given
		help start-test
		return
	fi

	stop-test

	# Make sure times are similar (only used for processing)
	# TBD remove once NTP works
	set-time

	echo Setting latency to $3
	set-latency $3

	clean-pushed

	echo Starting collection
	start-collection

	echo Beginning experiment $1 with hop rate $4
	start-arg $4
	start-generators $1

	echo Running experiment $1 with hop rate $4 for $2 seconds
	eraseline="\r                                \r"
	i=$2
	while (( $i ))
	do
		echo -ne "$eraseline$i seconds remaining"
		sleep 1
		i=$(($i - 1))
	done
	echo -e "${eraseline}Done running tests"

	echo Ending experiment $1
	stop-test

	d="`date +%Y-%m-%d-%H:%M:%S`-t$1-l$3-hr$4ms"
	echo Pulling logs into $RESULTSDIR/$d
	clean-pulled
	retrieve-logs "$d"
}

# Ensures all components of a test are dead (gateways, collectors, etc)
# Usage: stop-test
function stop-test {
	stop-generators
	stop-collection
	stop-arg
}

# Starts traffic generators on the network for the appropriate test
# Test number may be one of:
#	0 - Connectivity test (slow packets between each pair that should be able to communicate)
#	1 - Flood legitimate
#	2 - Flood illegitimate
#	3 - Replay
# Usage: start-generators <test num>
function start-generators {
	if [[ $IS_LOCAL ]]
	then
		push-to $EXT $PROT - scripts/gen_traffic.py
		run-on $EXT $PROT - start-generators $1
	else
		# What test are we running?
		if [[ "$1" == "0" ]]
		then
			# Simple test to check connectivity
			if [[ "$TYPE" == "ext" ]]
			then	
				start-generator udp 2000
			else
				start-generator udp 3000
				start-generator udp 2000 172.100.0.1 5
				
				if [[ "$HOST" == "protA1" ]]
				then
					start-generator udp 3000 172.2.0.11 5
					start-generator udp 3000 172.3.0.11 5
				elif [[ "$HOST" == "protB1" ]]
				then
					start-generator udp 3000 172.1.0.11 5
					start-generator udp 3000 172.3.0.11 5
				elif [[ "$HOST" == "protC1" ]]
				then
					start-generator udp 3000 172.1.0.11 5
					start-generator udp 3000 172.2.0.11 5
				fi
			fi
		else
			# What host are we?
			if [[ "$TYPE" == "ext" ]]
			then
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
	mv "$PULLDIR" "$RESULTSDIR/$1"
	mkdir -p "$PULLDIR"
	rm -f "$RESULTSDIR/$1/config.log"
	rm -f "$RESULTSDIR/$1/build.log"
	rm -f "$RESULTSDIR/$1/$RUNDB"

	echo Results saved to "$RESULTSDIR/$1"
}

# Process all runs in the results director. Farms them out to test hosts
# for processing, allowing us to parallelize the work.
# Usage: process-runs
function process-runs {
	if [[ ! $IS_LOCAL ]]
	then
		echo Must be run from local
		return
	fi

	clean-pushed

	export gateA=00
	export gateB=00
	export gateC=00
	export protA1=00
	export protB1=00
	export protC1=00
	export ext1=00
	for results in $RESULTSDIR/*
	do
		# Don't handle if it has already been processed
		if [ -f "$results/$RUNDB" ]
		then
			continue
		fi

		echo Finding a host to process $results	

		while (( 1 ))
		do
			if [ -z "`ps ax | grep -E \"^\s*$gateA\"`" ]
			then
				process-run-remote gateA "$results" &
				gateA=$!
				break
			elif [ -z "`ps ax | grep -E \"^\s*$gateB\"`" ]
			then
				process-run-remote gateB "$results" &
				gateB=$!
				break
			elif [ -z "`ps ax | grep -E \"^\s*$gateC\"`" ]
			then
				process-run-remote gateC "$results" &
				gateC=$!
				break
			elif [ -z "`ps ax | grep -E \"^\s*$protA1\"`" ]
			then
				process-run-remote protA1 "$results" &
				protA1=$!
				break
			elif [ -z "`ps ax | grep -E \"^\s*$protB1\"`" ]
			then
				process-run-remote protB1 "$results" &
				protB1=$!
				break
			elif [ -z "`ps ax | grep -E \"^\s*$protC1\"`" ]
			then
				process-run-remote protC1 "$results" &
				protC1=$!
				break
			elif [ -z "`ps ax | grep -E \"^\s*$ext1\"`" ]
			then
				process-run-remote ext1 "$results" &
				ext1=$!
				break
			fi

			# Don't try again too soon
			echo Waiting for a slot to open up to process $results
			sleep 10
		done

		sleep 1
	done

	# Make sure everything finishes
	echo Waiting for final processing to complete
	wait
	echo All processing completed

	clean-pulled
}

# Shows the results of all processed runs in the results directory.
# If offset is given, results are displayed without the first and last
# <offset> seconds in the run included.
# Usage: show-results [<offset>]
function show-results {
	if [[ "$#" == "0" ]]
	then
		offset=0
	else
		offset=$1
	fi

	# Show final results
	for results in $RESULTSDIR/*
	do
		echo -e '\n############################################'
		echo Showing results for $results

		if [ -f "$results/$RUNDB" ]
		then
			scripts/process_run.py -l "$results" -db "$results/$RUNDB" \
				--skip-trace --start-offset $offset --end-offset $offset
		else
			echo Run not processed yet
		fi
	done
}

# Removes all run databases, allowing process-results to regenerate
# all data from scratch
# Usage: clean-processed
function clean-processed {
	if [[ ! $IS_LOCAL ]]
	then
		echo Must be run from local
		return
	fi

	rm -f $RESULTSDIR/*/run.db
}

# Process a given run's results on a remote host
# Usage: process-run <host> <results dir>
function process-run-remote {
	if [[ $IS_LOCAL ]]
	then
		if [[ "$#" != "2" ]]
		then
			echo Not enough parameters given
			help process-run-remote
		fi

		echo Processing $2 on $1

		clean-pushed "$1"
		push-to "$1" - scripts/process_run.py "$2"
		base=`basename "$2"`
		run-on "$1" - process-run-remote "$base"

		# Prevent one result overwriting another
		backoff=$(($RANDOM % 20 + 2))
		wait_count=0
		while [ -f "$PULLDIR/$RUNDB" ]
		do
			echo $1 waiting for $RUNDB to disappear
			sleep $(($RANDOM % 5))

			# Wait a random number of seconds before continuing regardless. Prevents us getting
			# locked and noone removing the $RUNDB file
			wait_count=$(($wait_count + 1))

			if [ -f "$PULLDIR/reset_counts" ]
			then
				wait_count=0
			fi

			if (( $wait_count > $backoff ))
			then
				echo $1 brashly continuing on, taking care of frozen $RUNDB

				# Tell everyone else we're taking this
				touch "$PULLDIR/reset_counts"
				sleep 10
				rm "$PULLDIR/reset_counts"
				break
			fi
		done

		clean-pulled
		touch "$PULLDIR/$RUNDB"

		pull-from "$1" - "$RUNDB"
		pull-from "$1" - "$PROCESSLOG"
		mv "$PULLDIR/$RUNDB" "$2/$RUNDB"
		mv "$PULLDIR/$PROCESSLOG" "$2/$PROCESSLOG"

		echo Completed processing of $2 on $1
	else
		# TBD change back
		./process_run.py -l "$1" -db "$RUNDB" 2>&1 | tee "$PROCESSLOG"
	fi
}

# Stops any processing occuring 
# Usage: stop-processing
function stop-processing {
	if [[ $IS_LOCAL ]]
	then
		push-to $ALL
		run-on $ALL - stop-processing
	else
		_stop-process python
	fi
}

# Run-make does a full build on _all_ gates and saves the binary to ~
# Intended for setting up tests, ssh into the gateway should be used for development
# Usage: run-make
function run-make {
	if [[ $IS_LOCAL ]]
	then
		push-to gateA - conf *.c *.h autogen.sh configure.ac Makefile.am
		run-on gateA - run-make 
		pull-from gateA - build.log

		# Check build log for status
		if ! grep 'make.*Error' "$PULLDIR/build.log" >/dev/null
		then
			# All good
			pull-from gateA - arg
			mv "$PULLDIR/arg" .
			clean-pulled 
			return 0
		else
			echo Errors found during build
			return 1
		fi
	else
		stop-arg 
		rm -f install.sh
		./autogen.sh && make clean && make 2>&1 | tee build.log 
	fi
}

# Builds ARG from scratch and runs it on all gateways. Hops
# every <hop rate> milliseconds.
# Usage: start-arg <hop rate>
function start-arg {
	if [[ $IS_LOCAL ]]
	then
		if [[ "$#" != 1 ]]
		then
			echo Hop rate must be given
			help start-arg
			return 
		fi

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
}

# Network setup changes
# Changes the latency on the delay box to the given value. 
# Latency values are given with their units, e.g., 30ms, 1s, etc
# Usage: set-latency <delay to all>
#        set-latency <delay to gates> <delay to external>
#        set-latency <delay to gate A> <delay to B> <delay to ext>
function set-latency {
	if [ -z $LATENCY ]
	then
		echo No latency servers available, unable to set
		return
	fi

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
		toExt=`expr $toExt '*' 1000`
		toA=`expr $toA '*' 1000`
		toB=`expr $toB '*' 1000`
		sudo tc qdisc replace dev eth1 root netem delay "$toExt"
		sudo tc qdisc replace dev eth2 root netem delay "$toA"
		sudo tc qdisc replace dev eth3 root netem delay "$toB"
	fi
}

# Sets all server times to the time of the local machine
# Usage: set-time
function set-time {
	if [[ $IS_LOCAL ]]
	then
		push-to $ALL
		run-on $ALL - set-time "`date '+%m/%d/%Y +%H:%M:%S'`"
	else
		sudo date -s "$@"
	fi
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
}

# Shuts down all servers
# Usage: shutdown
function shutdown {
	if [[ $IS_LOCAL ]]
	then
		push-to $ALL $LATENCY -
		run-on $ALL $LATENCY - shutdown/
	else
		sudo shutdown -h 0
	fi
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
		#echo 1 > /proc/sys/net/ipv4/ip_forward
		sudo brctl addbr br0
		sudo brctl addif br0 eth1
		sudo brctl addif br0 eth2
		sudo ifconfig br0 up
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
		#echo 0 > /proc/sys/net/ipv4/ip_forward
		sudo ifconfig br0 down
		sudo brctl delbr br0
	fi
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
		if [[ `ps -A | grep " $1$"` == "" ]]
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
}

# Installs the packages necessary to build ARG on the gates
# Usage: setup-gate-env
function setup-gate-env {
	if [[ $IS_LOCAL ]]
	then
		push-to $GATES
		run-on $GATES - setup-gate-env 
	else
		sudo apt-get -y update
		sudo apt-get -y dist-upgrade
		sudo apt-get -y install build-essential autoconf automake libtool libpcap-dev libpolarssl-dev bridge-utils
	fi
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
}

# Removes all files in the 'pushed' directory on every server. If a
# host is given, only that host is cleaned, otherwise all of them are
# Usage: clean-pushed [<host>] [<host>] [...]
function clean-pushed {
	if [[ $IS_LOCAL ]]
	then
		if [[ "$#" == "0" ]]
		then
			push-to $ALL -  
			run-on $ALL - clean-pushed
		else
			push-to $@ -  
			run-on $@ - clean-pushed
		fi
	else
		sudo rm -rf *
	fi
}

# Removes all files in the 'pulled' directory on local system
# Usage: clean-pulled
function clean-pulled {
	if [[ ! $IS_LOCAL ]]
	then
		echo Must be run from local
		return
	fi
	
	mkdir -p "$PULLDIR"
	rm -rf "$PULLDIR/*"
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
	if [[ "$LOCAL" == "$TYPE" || "$HOST" == "dev" ]]
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

