CC ?= cc
CFLAGS ?= -O2 -g -std=c11 -Wall -Wextra -Werror

build/guard-rm: src/guard_rm.c src/scope.c src/scope.h
	mkdir -p build
	$(CC) $(CFLAGS) src/guard_rm.c src/scope.c -lcrypto -o $@

test: build/guard-rm
	python3 -m unittest discover -s tests -v

.PHONY: test
