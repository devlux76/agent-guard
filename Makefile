CC ?= cc
CFLAGS ?= -O2 -g -std=c11 -Wall -Wextra -Werror

build/guard-rm: src/guard_rm.c
	mkdir -p build
	$(CC) $(CFLAGS) $< -lcrypto -o $@

test: build/guard-rm
	python3 -m unittest discover -s tests -v

.PHONY: test
