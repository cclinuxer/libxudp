build=../objs

ifdef SO
LDFLAGS += -L $(build) -l xudp
else
LDFLAGS += $(build)/libxudp.a -l elf -l pthread
endif

CFLAGS += -g -O2 -Wall -I $(build)

ALL += $(build)/xudpperf
ALL += $(build)/xudp-echo-server

all: $(ALL)

$(build)/tools/%.o: %.c
	@echo PC $@
	@mkdir $(shell dirname $@) 2>/dev/null || true
	@clang $< $(CFLAGS) -fPIC -c -o $@

$(build)/xudpperf: $(build)/tools/xudpperf.o
	@echo LD $@
	@clang $^ $(LDFLAGS) -o $@ -l pthread

$(build)/xudp-echo-server: $(build)/tools/xudp_echo_server.o
	@echo LD $@
	@clang $^ $(LDFLAGS) -o $@

