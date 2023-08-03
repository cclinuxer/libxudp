
ALL := $(filter test%.c, $(shell ls case))
ALL := $(ALL:%.c=bin/%)
ALL += bin/lib.o

all: clean $(ALL)

run: $(ALL)
	sh route6.sh
	python2 route6.py
	sh netns.sh
	echo "test for ipv4"
	python3 -m pytest --durations=0  auto/ $(pytest)
	echo "test for ipv6"
	python3 -m pytest --durations=0  auto/ $(pytest) --ipv6

bin/lib.o: case/lib.c
	@echo CC lib.o
	@mkdir bin 2>/dev/null || true
	@gcc  $^ -I ../objs/ -l elf -l pthread -fPIC -c -o $@ -g

bin/test_%: case/test_%.c bin/lib.o
	@echo CC $@
	@mkdir bin 2>/dev/null || true
	@gcc $^ -o $@ -I ../objs/  ../objs//libxudp.a -fPIC -l elf -l pthread -g


clean:
	rm -rf bin



