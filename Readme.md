## Express UDP

Express UDP is a high-performance UDP communication software library based on
the xdp socket technology introduced in kernel 4.18.

[Chinese Readme](Readme-cn.md)

## make & install

```
yum install libnl3-devel elfutils-libelf-devel clang llvm libcap-devel
make
```

All output is in the objs directory. At the same time, there are libxudp.a and
libxudp.so files and the header file xudp.h.

## Experience It

tools/xudp\_echo\_server.c is a simple echo service implementation. The compiled
file is under objs, command format:

```
./xudp-echo-server <ip> <port>
```

ip is the local address to be bound, if you use 0.0.0.0, all network cards will
be monitored. The details will be introduced later. After startup, you can use
the following command to test:

```
nc -u <ip> <port>
```


Send udp message to the server, the server will print the message and echo to
the client.

## ARP

There is currently a rudimentary ARP implementation. Since Alibaba Cloud has ARP
Proxy support, opening the libxudp noarp option can work in Alibaba Cloud
without the related overhead of arp.

It is currently recommended to turn on the noarp option on Alibaba Cloud.

