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


import xudp
import struct
import time

proc = "test_fork"
killall = True

def req(key):
    fd = xudp.get_con()

    fd.sendto(key, '')
    buf = fd.recv(1024)

    i, total, tid = buf.split('/')
    return int(i)

def check(key):
    fd = xudp.get_con()

    fd.sendto(key, '')
    buf = fd.recv(1024)

    i, total, tid = buf.split('/')

    assert int(i) == key

    return int(total)

def try_group_restart(gid):
    fd = xudp.get_con()
    fd.sendto(gid, '')
    buf = fd.recv(1024)

    pid = buf.split('/')[2]

    xudp.get_con().sendto(gid, "AGAIN")
    xudp.check_group_wakeup(gid, int(pid))

def dict_check():
    total = check(0)

    for i in range(total):
        for n in range(100):
            check(i)

    ids = []
    for i in range(10000, 10050):
        for n in range(10):
            gid = req(i)
            ids.append(gid)

    ids = set(ids)

    assert len(ids) > 3

def test_dict_check(proc):
    dict_check()

def test_again(proc):
    xsk_n = xudp.xsk_num()

    try_group_restart(5)
    check(5)

    assert xsk_n == xudp.xsk_num()

def test_exit(proc):
    gid = 6
    udp = xudp.get_con()

    udp.sendto(gid, "EXIT")

    time.sleep(0.5)

    for n in range(200):
        udp.sendto(gid, '')
        buf = udp.recv(1024)
        i, total, tid = buf.split('/')
        assert int(i) != gid


def test_again1(proc):
    xsk_n = xudp.xsk_num()

    for i in range(0, 10):
        try_group_restart(5)
        check(5)
        assert xsk_n == xudp.xsk_num()


