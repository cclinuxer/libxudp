# -*- coding:utf-8 -*-

import os

class g(object):
    nic = 'dummy0'
    netns = "xudp-ipv6-route"
    setup_dump = False
    xudp_dump = False
    check_dump = True

def shell(cmd, prefix = '>      ', pipe = False, echo = True, dump = False):
    cmd = "ip netns exec %s %s" % (g.netns, cmd)

    if echo:
        print "> ", cmd

    lines = os.popen(cmd).readlines()

    if pipe:
        return lines

    for l in lines:
        print "%s%s" % (prefix, l[0:-1])

    if dump:
        _dump()


def addr_add(addr, dev = 'dummy0'):
    shell("ip -6 addr add %s dev dummy0" % addr)
    g.check_dump = True

def route_add(dst, via = None, dev = 'dummy0'):
    shell("ip -6 route add %s dev %s" % (dst, dev))
    g.check_dump = True

    return dst


def dump():
    print ">  DUMP OS route:"
    shell('ip -6 route', echo = False)
    print ">  DUMP XUDP route:"
    shell('../objs/xudp-route6', echo = False)
    print ""

def _dump():
    dump()


class check(object):
    def __init__(self, target, index = None,
            ifid = None, dstlen = 0, dst = "::", via = "::", src = "::"):

        if g.check_dump:
            g.check_dump = False
            dump()

        self.target = target
        self.index  = index
        self.ifid   = ifid
        self.dst    = dst
        self.dstlen = dstlen
        self.via    = via
        self.src    = src

        self.check_done = 0

        if self.dst.find('/') > -1:
            self.dst, self.dstlen = self.dst.split('/')
            self.dstlen = int(self.dstlen)

        print("check %s index: %s dst: %s/%2s via: %s src: %s" % (self.target,
            self.index, self.dst, self.dstlen, self.via, self.src))

        self.test()

    def check(self, key, value):
        try:
            if key == 'target':
                assert self.target == value
                self.check_done += 1

            if key == 'index' and self.index != None:
                assert self.index == int(value)
                self.check_done += 1

            if key == 'ret':
                assert int(value) == 1
                self.check_done += 1

            #if key == 'ifid':
            #    assert self.ifid == int(value)

            if key == 'dstlen':
                assert self.dstlen == int(value)
                self.check_done += 1

            if key == 'dst':
                assert self.dst == value
                self.check_done += 1

            if key == 'via':
                assert self.via == value
                self.check_done += 1

            if key == 'src':
                assert self.src == value
                self.check_done += 1

        except Exception as e:
            raise(Exception("key: %s value: %s" % (key, value)))

    def test(self):


        if g.xudp_dump:
            cmd = 'ip -6 route get %s' % self.target
            shell(cmd)

        cmd = "../objs/xudp-route6 %s" % self.target

        lines = shell(cmd, pipe = True, echo = False)

        for line in lines:
            if g.xudp_dump:
                print line,

            if not line:
                continue

            line = line.strip()

            t = line.split(":", 1)
            if len(t) != 2:
                continue

            key, value = t
            self.check(key.strip(), value.strip())

        assert self.check_done > 5

        if g.xudp_dump:
            print ""

def run_test():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--xudp-dump", action='store_true')
    args = parser.parse_args()

    g.xudp_dump = args.xudp_dump

    keys = globals().keys()
    keys.sort()
    for name in keys:
        if name.startswith('test_'):
            fun = globals()[name]
            setup(name)
            fun()


def setup(name):
    print ""
    print "> ======= [%s] - setup ============" % name
    shell("ip link del %s" % g.nic, echo = False)
    shell("ip link set dev lo up", echo = False)
    shell("ip link add dummy0 type dummy", echo = False)
    shell("ip link set dev dummy0 up", echo = False)
    if g.setup_dump:
        dump()


# check for not default
def test_10():
    addr_add(      "1234:5678:abcd:1234::100/64")
    R1 = route_add("1234::/16")

    check("1234:F000::", dst = R1)
    check("123F::") # not default

def test_11():
    addr_add(      "1234:5678:abcd:1234::100/64")
    R1 = route_add("1234::/16")
    R2 = route_add("1234:5600::/24")

    check("1234:56FF::", dst = R2)
    check("123F::") # not default

def test_12():
    addr_add(      "1234:5678:abcd:1234::100/64")
    R1 = route_add("1234:5678::/32")

    check("1234:5678:9::", dst = R1)
    check("123F::") # not default

def test_13():
    addr_add(      "1234:5678:abcd:1234::100/64")
    R1 = route_add("1234:5600::/24")
    R2 = route_add("1234:5678::/32")
    R3 = route_add("1234:5678:9000::/40")
    R4 = route_add("1234:5678:9012::/48")
    R5 = route_add("1234:5678:9012:3400::/56")
    R6 = route_add("1234:5678:9012:3456::/64")

    check("1234:56FF::",                dst = R1)
    check("1234:5678:1::",              dst = R2)
    check("1234:5678:9014::",           dst = R3)
    check("1234:5678:9012::",           dst = R4)
    check("1234:5678:9012:3412::",      dst = R5)
    check("1234:5678:9012:3456:FF00::", dst = R6)

def test_14():
    addr_add(      "1234:5678:abcd:1234::100/64")
    R6 = route_add("1234:5678:9012:3456::/64")

    check(         "1234:5678:9012:3456:FF00::", dst = R6)

def test_21():
    addr_add(      "1234:5678:abcd:1234::100/64")

    R1 = route_add("1234:100::/24")
    R2 = route_add("1234:200::/24")
    R3 = route_add("1234:400::/24")

    R4 = route_add("1234:1234:1234:1234:100::/72")
    R5 = route_add("1234:1234:1234:1234:200::/72")
    R6 = route_add("1234:1234:1234:1234:400::/72")

    R7 = route_add("1234:A30F::/30")

    check("1234:101::", dst = R1)
    check("1234:201::", dst = R2)
    check("1234:401::", dst = R3)

    check("1234:1234:1234:1234:101::", dst = R4)
    check("1234:1234:1234:1234:201::", dst = R5)
    check("1234:1234:1234:1234:401::", dst = R6)

def test_20():
    addr_add(      "1234:5678:abcd:1234::100/64")

    R1 = route_add("1234:a000::/20")
    R2 = route_add("1234:a300::/24")
    R3 = route_add("1234:a3a0::/28")
    R4 = route_add("1234:a3a8::/32")

    check("1234:AF00::",  dst = R1)
    check("1234:A3F0::",  dst = R2)
    check("1234:A3A1::",  dst = R3)
    check("1234:A3A8:1::", dst = R4)


def test_30():
    addr_add(      "1234:5678:abcd:1234::100/64")

    R1 = route_add("1234:a300::/24")
    R2 = route_add("1234:a3a8::/32")
    R3 = route_add("1234:a3a8:1000::/40")

    check("1234:A3A9::", dst = R1)
    check("1234:A3A8:2000::", dst = R2)
    check("1234:A3A8:1010::", dst = R3)

run_test()


