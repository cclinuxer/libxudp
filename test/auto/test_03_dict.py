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
from collections import defaultdict
import struct

def check(udp, key):
    udp.sendto(key, '')
    buf = udp.recv(1024)

    i, total, tid = buf.split('/')

    assert int(i) == key

    return int(total)

def test_dict(proc):
    pids = defaultdict(int)

    udp = xudp.get_con()

    total = check(udp, 0)

    for i in range(total):
        for n in range(100):
            check(udp, i)


