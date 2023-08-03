#!/usr/bin/env sh

ip netns exec xudp-ipv6-route ip link > /dev/null 2>/dev/null
ret=$?

if (( $ret != 0 ))
then
	echo "create netns xudp-ipv6-route"
	ip netns add xudp-ipv6-route
	ip netns exec xudp-ipv6-route ip link set lo up
fi

