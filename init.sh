#!/bin/bash -e
ifconfig eth1 0.0.0.0 promisc up
ifconfig eth2 0.0.0.0 promisc up
brctl addbr br0
brctl setfd br0 0
brctl sethello br0 0
brctl addif br0 eth1
brctl addif br0 eth2
brctl stp br0 off
ifconfig br0 up
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
echo 0 > /proc/sys/net/ipv4/ip_forward
echo 0 > /proc/sys/net/ipv4/tcp_syncookies