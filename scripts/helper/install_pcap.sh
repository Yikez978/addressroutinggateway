#!/bin/bash
PCAP_DIR=~/src/libpcap

echo Installing flex and bison if needed...
sudo apt-get update
sudo apt-get install -y flex bison

if [ ! -e "$PCAP_DIR" ]
then
	echo Download pcap...
	mkdir -p "$PCAP_DIR"
	git clone git://bpf.tcpdump.org/libpcap "$PCAP_DIR"
	cd "$PCAP_DIR"
else
	echo Updating pcap SVN...
	cd "$PCAP_DIR"
	git pull
fi

echo Downloading pcap again... stupid tar.gz
cd ~/src
wget http://www.tcpdump.org/release/libpcap-1.3.0.tar.gz

echo Extracting pcap archive...
tar -xzf libpcap-*.tar.gz
cd libpcap-*

echo Building pcap...
./configure || exit 1
make

echo Installing...
sudo make install

echo Done!

