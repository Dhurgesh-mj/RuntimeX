CC ?= cc
CFLAGS ?= -g -O0 -fno-omit-frame-pointer -Wall -Wextra
ASAN_FLAGS ?= -g -O0 -fno-omit-frame-pointer -fsanitize=address -fno-common

.PHONY: all asan clean

all: target

target: target_demo.c
	$(CC) $(CFLAGS) -o $@ $<

asan: target_asan

target_asan: target_demo.c
	$(CC) $(ASAN_FLAGS) -o $@ $<

clean:
	rm -f target target_asan target.exe target_asan.exe
