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

ifdef XUDP_DEBUG
CFLAGS += -DXUDP_DEBUG=1
CFLAGS += -g -Wall -I /usr/include/libnl3
else
CFLAGS += -O2 -g -Wall -I /usr/include/libnl3
endif


CFLAGS_common=$(CFLAGS) -I include
CFLAGS_bpf= $(CFLAGS) -I common
CFLAGS_xudp= $(CFLAGS) -I common -I include -I kern -I bpf
CFLAGS_group= $(CFLAGS) -I common -I include -I kern -I bpf

################################################################################

ALL += objs/libxudp.so.$(VERSION)
ALL += objs/libxudp.a
ALL += objs/xudp-map
ALL += objs/xudp-dump
ALL += objs/xudp-route
ALL += objs/xudp-route6

LIBXUDP += objs/common/ifapi.o
LIBXUDP += objs/common/log.o
LIBXUDP += objs/bpf/bpf.o

LIBXUDP += objs/xudp/xudp.o
LIBXUDP += objs/xudp/bind.o
LIBXUDP += objs/xudp/packet.o
LIBXUDP += objs/xudp/route.o
LIBXUDP += objs/xudp/route6.o
LIBXUDP += objs/xudp/neigh.o
LIBXUDP += objs/xudp/ping.o
LIBXUDP += objs/xudp/xsk.o
LIBXUDP += objs/xudp/tx.o
LIBXUDP += objs/xudp/group_api.o

LIBXUDP += objs/group/channel.o
LIBXUDP += objs/group/group.o
LIBXUDP += objs/group/dump.o

LIBXUDP += objs/kern/em_kern_hash.o
LIBXUDP += objs/kern/em_kern_dict.o
LIBXUDP += objs/kern/em_kern_rr.o

LIBXUDP += objs/xudp/kern_ops.o

VER_X=1
VER_Y=0
VER_Z=2

SONAME=libxudp.so.1
VERSION=$(VER_X).$(VER_Y).$(VER_Z)
VERSION_INT=1000000000

prefix = /usr/local


################################################################################

.PHONY: all clean test kern

all: clean $(ALL)
	make -C tools SO=$(SO)

objs/%.o: %.c
	@echo CC $@
	@mkdir $(shell dirname $@) 2>/dev/null || true
	@gcc $< $(CFLAGS_$(shell dirname $<)) -fPIC -c -o $@

objs/kern/em_kern_%.o:
	make -C kern XUDP_DEBUG=$(XUDP_DEBUG) ../$@

# this for custom xdp bpf.
# $(srcdir) is the source dirname
# $(target)
kern:
	make -C kern XUDP_DEBUG=$(XUDP_DEBUG) \
		build=$(srcdir) \
		srcdir=$(srcdir) \
		$(srcdir)/$(target)

objs/libxudp.so.$(VERSION): $(LIBXUDP)
	@echo LD $@
	@gcc $^ -lelf -shared -o $@  -Wl,-soname,$(SONAME) -l pthread
	@rm objs/xudp.h 2>/dev/null || true
	@cp include/xudp.h objs
	@echo '#define XUDP_HASH "'$(shell git rev-parse --short HEAD)'"' >> objs/xudp.h
	@echo '#define XUDP_VERSION "'$(VERSION)'"' >> objs/xudp.h
	@echo '#define XUDP_VERSION_INT '$(VERSION_INT) >> objs/xudp.h
	@ln -s libxudp.so.$(VERSION) objs/libxudp.so
	@ln -s libxudp.so.$(VERSION) objs/libxudp.so.$(VER_X)

objs/libxudp.a: $(LIBXUDP)
	@echo AR $@
	@ar rcs $@ $^

objs/xudp-map: objs/xudp/xudp_map.o
	@gcc $^ $(LDFLAGS) -o $@ -l pthread

objs/xudp-dump: objs/group/xudp_dump.o
	@gcc $^ $(LDFLAGS) -o $@ -l pthread

objs/xudp-route: objs/xudp/route.o objs/xudp/xudp_route.o objs/common/ifapi.o objs/common/log.o
	@gcc $^ $(LDFLAGS) -o $@

objs/xudp-route6: objs/xudp/route6.o objs/xudp/xudp_route6.o objs/common/ifapi.o objs/common/log.o
	@gcc $^ $(LDFLAGS) -o $@

test:
	make -C test

test_run:
	make -C test run pytest="$(pytest)"

clean:
	-mkdir objs 2>/dev/null
	rm -rf objs/*

install:
	cp objs/xudp.h $(prefix)/include/
	cp -P objs/libxudp.so $(prefix)/lib64/
	cp -P objs/libxudp.so.$(VER_X) $(prefix)/lib64/
	cp objs/libxudp.so.$(VERSION) $(prefix)/lib64/
	cp objs/libxudp.a $(prefix)/lib64/
	cp objs/xudpperf $(prefix)/bin/
	cp objs/xudp-echo-server $(prefix)/bin/
	cp objs/xudp-map $(prefix)/bin/
	cp objs/xudp-dump $(prefix)/bin/
	cp tools/xudp-stats $(prefix)/bin/
	cp objs/xudp-route $(prefix)/bin/
	cp objs/xudp-route6 $(prefix)/bin/

uninstall:
	rm $(prefix)/include/xudp.h
	rm $(prefix)/lib64/libxudp.so
	rm $(prefix)/lib64/libxudp.a
	rm $(prefix)/bin/xudpperf
	rm $(prefix)/bin/xudp-echo-server
	rm $(prefix)/bin/xudp-map
	rm $(prefix)/bin/xudp-stats
