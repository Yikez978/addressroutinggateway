#!/bin/bash
# Installs VMWare tools
# Update
sudo apt-get -y update
sudo apt-get -y dist-upgrade

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

