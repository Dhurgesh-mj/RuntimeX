CC ?= cc
CFLAGS ?= -g -O0 -fno-omit-frame-pointer -Wall -Wextra
ASAN_FLAGS ?= -g -O0 -fno-omit-frame-pointer -fsanitize=address -fno-common

TARGETS = target \
          heap_overflow_demo \
          use_after_free_demo \
          double_free_demo \
          memory_leak_demo \
          integer_overflow_demo

.PHONY: all asan clean $(TARGETS)

all: $(TARGETS)

target: target_demo.c
	$(CC) $(CFLAGS) -o $@ $<

heap_overflow_demo: heap_overflow_demo.c
	$(CC) $(CFLAGS) -o $@ $<

use_after_free_demo: use_after_free_demo.c
	$(CC) $(CFLAGS) -o $@ $<

double_free_demo: double_free_demo.c
	$(CC) $(CFLAGS) -o $@ $<

memory_leak_demo: memory_leak_demo.c
	$(CC) $(CFLAGS) -o $@ $<

integer_overflow_demo: integer_overflow_demo.c
	$(CC) $(CFLAGS) -o $@ $<

asan: target_asan

target_asan: target_demo.c
	$(CC) $(ASAN_FLAGS) -o $@ $<

clean:
	rm -f $(TARGETS) target_asan *.exe
