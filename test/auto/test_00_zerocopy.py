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
import time
import os


proc = 'test_log_debug'
wait_init = False

def test_check_zc(proc):
    zerocpy = False


    s = time.time()
    while True:
        if time.time() - s > 5:
            raise Exception("wait too long.")

        line = proc.stdout.readline()
        line = line.strip()

        if not line:
            continue

        print(line)

        if line.endswith('Success zero copy: true'):
            zerocpy = True

        if line.find('bind success.') > -1:
            break



    assert zerocpy


def test_eth_channel_num(proc):
    cmd = "ip netns exec xudp ethtool -l eth1 |grep Combined | tail -n 1 | cut -d : -f 2"
    n = os.popen(cmd).read().strip()
    n = int(n)

    """
        limit the eth1 channel num < 5
        some test cases depend this
    """
    assert(n < 5)

