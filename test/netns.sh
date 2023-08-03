#!/usr/bin/env sh

ETH0=eth0
ETH1=eth1

ip netns exec xudp ip link > /dev/null 2>/dev/null
ret=$?

if (( $ret != 0 ))
then
	echo "create netns xudp"

	ip netns add xudp
	ip link set $ETH1 netns xudp

	ip addr add 10.0.35.1/24 dev $ETH0
	ip -6 addr add 1000:2000:3000:4000::1/64 dev $ETH0

	ip netns exec xudp ip addr add 10.0.35.2/24 dev $ETH1
	ip netns exec xudp ip -6 addr add 1000:2000:3000:4000::2/64 dev $ETH1
	ip netns exec xudp ip link set $ETH1 up
	ip netns exec xudp ip link set lo up
fi
