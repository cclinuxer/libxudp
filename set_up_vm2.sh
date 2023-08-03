#!/bin/bash
#创建2个namespace
insmod /mnt/nfs/bare_metal_kernel/linux-ste-kernel/linux-image-bsk/drivers/net/veth.ko
ip netns add ns1
ip netns add ns2
#创建一个linux bridge
brctl addbr virtual-bridge

ip link add veth-ns1 type veth peer name veth-br1
ip link set veth-ns1 netns ns1
brctl addif virtual-bridge veth-br1

ip link add veth-ns2 type veth peer name veth-br2
ip link set veth-ns2 netns ns2
brctl addif virtual-bridge veth-br2

ip -n ns1 addr add local 192.168.2.2/24 dev veth-ns1
ip -n ns2 addr add local 192.168.2.3/24 dev veth-ns2
ip addr add local 192.168.2.1/24 dev virtual-bridge

ip link set virtual-bridge up
ip link set veth-br1 up
ip link set veth-br2 up
ip -n ns1 link set veth-ns1 up
ip -n ns2 link set veth-ns2 up

#set default route
ip netns exec ns1 ip route add default via 192.168.2.1
ip netns exec ns2 ip route add default via 192.168.2.1

echo 1 > /proc/sys/net/ipv4/ip_forward

iptables -t nat -A POSTROUTING -s 192.168.2.0/24 -o eth0 -j MASQUERADE
