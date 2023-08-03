## Express UDP

Express UDP 是基于 XDP Socket 实现的 UDP 通信软件库.

### 收包

基于 XDP 在网卡驱动层对包进行过滤, 把指定 ip:port 的 udp 包传递给
XSK, 应用层 Express UDP 从 XSK 中收包。

### 发包
Express UDP 传递包给 XSK, XSK 把包构建 skb 并放入网卡队列中进行发包。XSK ZEROCOPY
模式下可以跳过构建 skb 的过程直接把包传递给网卡, 这样性能会更好。

## 构建与安装

```
yum install libnl3-devel elfutils-libelf-devel clang llvm libcap-devel
make
```

所有的输出在 objs 目录下面。
同时输出有 libxudp.a 和 libxudp.so 文件以及头文件 xudp.h。

## 体验一下
tools/xudp\_echo\_server.c 是一个简单的 echo 服务实现。编译后的文件在在 objs 下面, 命令格式:

```
./xudp-echo-server <ip> <port>
```
ip 为要 bind 的本地地址, 如果使用 0.0.0.0 会监听所有的网卡, 详细后面还会介绍。
启动之后可以使用如下命令进行测试:

```
nc -u <ip> <port>
```
发送 udp 消息给服务端, server 会打印消息并 echo 给客户端。

更多实践信息可见: [阿里云实践](https://openanolis.cn/sig/high-perf-network/doc/411142504638253189?preview=null)

## bind
这个过程主要是把 ebpf 与网卡进行绑定, 并且创建 xsk 再与和 ebpf 进行绑定。

注意, 一些网卡并不支持 xdp 如 lo, 所以目前 xudp 不能工作于这些网卡。

### 指定 ip 绑定
bind 过程中, Express UDP 会过滤所有的网卡, 对所有的符合 ip 指定的网卡都进行
bind 操作. 比如 0.0.0.0, xudp 会尝试 bind 所有的非 lo 网卡, 如果有一个网卡
bind 失败, 整个操作都视为失败。
bind 可以指定多个 struct sockaddr, 由参数 num 控制, 目前最多只支持 10 个。

```
int xudp_bind(xudp *x, struct sockaddr *a, socklen_t addrlen, int num);
```

## 多线程与多进程
由于现在一般网卡都是支持多队列的, 最好可以使用多线程或多进程进程编程。
recv/send 分别有两个接口, 默认情况下会轮询地对 channel 进行 recv/send
操作。带有 channel 后缀的接口, 只对指定的 channel 进行 recv/send 操作。

多线程或多进程的情况下, 一个线程或进程操作一个 channel, 会获得比较好的性能。

## epoll/poll/select
每一个 channel 可以基于 xudp\_channel\_getfd 获得对应的 xsk 的 fd,
这个 fd 支持epoll 操作, 可以用于 epoll/poll/select 对读写事件进行监听。

tools/xudp\_echo\_server.c 代码里有 epoll 的例子。

## 查看 XDP 的情况
新的版本的 iproute 可以直接查看, 配置网卡的 XDP.
笔者本地 iproute2-ss170501 已经支持这个功能了.

如果网卡有配置 xdp, 在 ip link 输出中有显示 xdp 字样。

命令 `ip link set <dev> xdp off` 可以关闭指定网卡的 XDP.

## 路由
目前 libxudp 已经支持路由, 也就是 client 和 server 可以不在同个网段, 也可以工作
于公网了。

Express UDP 在启动的时候获取本机的路由, 并保存在内存里面, 目前并不支持的路由修改和
同步。

路由的查找基于 hash 实现, 速度很快, 但是代价是要占用多一些内存空间。

## ARP

目前有一个简陋的 ARP 实现, 由于阿里云有 ARP Proxy 支持, 所以打开 libxudp
noarp 选项可以正常工作于阿里云, 并且没有 arp 的相关开销。

目前推荐在阿里云上打开 noarp 选项使用。

