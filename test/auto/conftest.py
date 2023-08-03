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

import pytest
import subprocess
import os

import sys
import signal
import time
import xudp

p = os.path.realpath(__file__)
p = os.path.dirname(p)

sys.path.append(p)

def pytest_addoption(parser):
    parser.addoption("--noproc", action="store_true")
    parser.addoption("--ipv6", action="store_true")

@pytest.fixture(scope='function')
def proc(request):
    noproc = request.config.getoption("--noproc")
    ipv6 = request.config.getoption("--ipv6")
    if ipv6:
        xudp.conf.ipv6 = True

    wait_init = False

    if noproc:
        proc = 'true'
        cmd = 'true with --noproc'
    else:
        cmd = None
        wait_init = getattr(request.module, 'wait_init', True)

        proc = getattr(request.module, 'proc', None)
        if not proc:
            proc = request.node.name


    p = xudp.proc_start(proc, wait_init = wait_init, cmd = cmd)

    yield p

    killall = getattr(request.module, 'killall', None)
    if killall:
        killall = proc

    xudp.proc_stop(p, killall)

