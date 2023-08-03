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
import time
import xudp

proc = "test_setuid_cap"
killall = True

class Test_with_keep_cap(object):
    keep_cap = '1'
    def setup(self):
        os.environ['keep_cap'] = self.keep_cap
        self.p = xudp.proc_start(proc)

    def teardown(self):
        xudp.proc_stop(self.p, killall = proc)

    def test_1(self):
        xudp.check_proc_wakeup()

        udp = xudp.get_con()

        udp.send('')
        msg1 = udp.recv(100)
        assert 3 == len(msg1.split('/'))


class Test_with_no_keep_cap(Test_with_keep_cap):
    keep_cap = '0'

    def setup(self):
        os.environ['keep_cap'] = self.keep_cap
        self.p = xudp.proc_start(proc, wait_init = False)

    def test_1(self):

        s = time.time()
        while True:
            if time.time() - s > 4:
                raise Exception("wait log too log")

            try:
                line = self.p.stdout.readline()
            except IOError:
                continue

            line = line.strip()
            if not line:
                continue

            print(line)

            if line == 'xudp: create AF_XDP fail. Operation not permitted.':
                return

            if line == 'xudp: txch ref shmat fail. Permission denied.':
                return



