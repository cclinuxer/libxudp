BPF_CFLAGS += -I..
BPF_CFLAGS += -I../include
BPF_CFLAGS += -I.
BPF_CFLAGS += -D__KERNEL__ -D__BPF_TRACING__
BPF_CFLAGS += -emit-llvm -c
BPF_CFLAGS += -O2 -g -Wall

LLC_FLAGS += -O2

#BPF_CFLAGS += -Wno-unused-value
BPF_CFLAGS += -Wno-unused-function
#BPF_CFLAGS += -Wno-pointer-sign
#BPF_CFLAGS += -Wno-compare-distinct-pointer-types
#BPF_CFLAGS += -Wno-gnu-variable-sized-type-not-at-end
#BPF_CFLAGS += -Wno-address-of-packed-member
#BPF_CFLAGS += -Wno-tautological-compare
#BPF_CFLAGS += -Wno-unknown-warning-option

ifeq ($(XUDP_DEBUG),1)
BPF_CFLAGS += -DXUDP_DEBUG=1
endif

build=../objs/kern
srcdir=./

.PRECIOUS: $(build)/kern_%.o

$(build)/kern_%.o: $(srcdir)/dispatch_%.c
	@mkdir $(build) 2>/dev/null || true
	@echo clang $(shell basename $@.bc)
	@clang $(BPF_CFLAGS) $^ -o $@.bc
	@echo 'llc  ' $(shell basename $@)
	@llc -march=bpf $(LLC_FLAGS) -filetype=obj $@.bc -o $@

$(build)/em_kern_%.o: $(build)/kern_%.o
	@echo 'LD   ' $(shell basename $@)
	@cd $(build); ld -r -b binary $(shell basename $<) -o $(shell basename $@)


clean:
	rm -rf $(build)
