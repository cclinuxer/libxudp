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

proc = 'test_echo'

def echo():
    udp = xudp.get_con()

    msg0 = 'abcdef'
    udp.send(msg0)
    msg1 = udp.recv(100)

    assert msg0 == msg1

def test_echo(proc):
    echo()


def test_echo_size(proc):
    udp = xudp.get_con()

    for i in range(0, 1400):
        msg0 = 'x' * i
        udp.send(msg0)
        msg1 = udp.recv(1500)

        assert msg0 == msg1

