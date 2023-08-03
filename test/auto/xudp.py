# -*- coding:utf-8 -*-
#
# Copyright (c) 2021 Alibaba Group Holding Limited
# Express UDP is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
#


import os
import subprocess
import time
import socket
import struct
import signal


def getid(gid):
    return struct.pack(">I", gid).decode('ascii')
class g:
    udp = None
    udp_noblock = None

class conf:
    addr = ("10.0.35.2", 3486)
    addr6 = ("1000:2000:3000:4000::2", 3487)
    ipv6 = False

def proc_start(name, wait_init = True, cmd = None):
    open("test.log", 'w')

    if not cmd:
        cmd = 'ip netns exec xudp ./bin/%s > test.log 2>&1' % name

    print ("\n$ %s" % cmd)

    p = subprocess.Popen(cmd, shell = True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)

    fd = open("test.log")
    p.stdout = fd

    if wait_init:
        import fcntl
        fl = fcntl.fcntl(p.stdout, fcntl.F_GETFL)
        fcntl.fcntl(p.stdout, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        start = time.time()
        while True:
            if time.time() - start > 3:
                    raise Exception("process init wait too long.")

            code = p.poll()
            if code != None:
                if code:
                    raise Exception("process exit code: %s" % code )
                else:
                    raise Exception("process exit")

            try:
                line = p.stdout.readline()
            except IOError:
                continue

            if not line:
                continue

            print(line[0: -1])
            if line.find('service ok.') > -1:
                break

    p.name = name
    return p

def proc_stop(p, killall = None):
    cmd = 'killall %s' % p.name
    os.system(cmd)

    s = time.time()
    while p.poll() == None:
        if time.time() - s > 10:
            raise Exception("process exit wait too long.")
        time.sleep(0.01)


class UDP(object):
    def __init__(self):
        if conf.ipv6:
            udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            udp.bind(('::', 0))
            udp.connect(conf.addr6)
        else:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind(('0.0.0.0', 0))
            udp.connect(conf.addr)

        udp.setblocking(0)

        self.udp = udp

    def send(self, msg):
        self.udp.send(bytes(msg, encoding='ascii'))

    def recv(self, s):
        # udp recvfrom may sleep, cannot wakeup
        while True:
            try:
                buf = self.udp.recv(s).decode('ascii')
                return buf
            except IOError:
                continue

    def sendto(self, gid, msg):
        m = struct.pack(">I", gid).decode('ascii') + msg
        self.send(m)

def get_con():
    return UDP()

def check_proc_wakeup():
    udp = UDP()

    msg = getid(0)

    while True:
        try:
            udp.udp.send(bytes(msg, encoding='ascii'))
            buf = udp.udp.recv(1024)
        except IOError:
            continue

        return True


def check_group_wakeup(gid, pid = None):
    udp = UDP()

    msg = bytes(getid(gid), encoding='ascii')

    while True:
        try:
            udp.udp.send(msg)
            buf = udp.udp.recv(1024).decode('ascii')
        except IOError:
            continue

        t = buf.split('/')
        if pid:
            if int(t[2]) == pid:
                continue
        if int(t[0]) == gid:
            return True

def check_group_exit(gid):
    udp = UDP()

    msg = getid(gid)

    while True:
        try:
            udp.udp.send(msg)
            buf = udp.udp.recv(1024)
        except IOError:
            continue

        t = buf.split('/')
        if int(t[0]) == gid:
            continue

        break



def xsk_num():
    cmd = "lsof |grep 'protocol: XDP' -c"
    n = os.popen(cmd).read().strip()
    return int(n)


