#!/bin/sh
sudo sysctl -w net.ipv4.neigh.default.gc_thresh3=65536
sudo sysctl -w net.ipv4.neigh.default.gc_thresh2=32768 
sudo sysctl -w net.ipv4.neigh.default.gc_thresh1=16384

