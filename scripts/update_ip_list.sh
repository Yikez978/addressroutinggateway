#!/bin/bash
# Must be run from one of the machines on the test network
HOSTS="172.100.0.1 172.1.0.1 172.1.0.11 172.2.0.1 172.2.0.11" 
CMD="hostname && ifconfig eth0 | grep 'inet addr'"
OUT="ips.txt"
SSHCONFIG="ssh_config"

# Grab names and IPs of each host
echo Getting data from hosts:
echo -n '' > "$OUT"
for ip in $HOSTS
do
	echo -e "\t$ip"
	ssh "$ip" "$CMD" >> "$OUT"
done

echo Final data:
cat "$OUT"

# Condense it down
echo Writing to SSH config $SSHCONFIG
echo -n '' > "$SSHCONFIG"
while read line
do
	echo Host $line >> "$SSHCONFIG"

	read line
	ip=`echo $line | awk '{print $2}' | sed -E 's/addr://'`
	echo -e "\tHostname $ip" >> "$SSHCONFIG"
	echo -e "\tUser traherom" >> "$SSHCONFIG"
	echo '' >> "$SSHCONFIG"
done < "$OUT"

rm "$OUT"

