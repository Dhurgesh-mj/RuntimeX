# RuntimeX Runtime Core (Person 1) — build configuration
#
# Supported environment: Linux x86_64, glibc, gcc/clang, dynamically linked
# targets. See docs/instrumentation-limitations.md.

CC      ?= gcc
CFLAGS  ?= -std=c11 -O2 -g
WARN     = -Wall -Wextra -Wshadow -Wno-unused-parameter
PIC      = -fPIC -fvisibility=hidden
DEFS     = -D_GNU_SOURCE
LD_FLAGS = -pthread -ldl

LIB_DIR   := preload
SHARED_DIR := shared
TARGET_DIR := targets
TEST_DIR   := tests
BUILD_DIR  := build
LOGS_DIR   := logs

LIB := $(BUILD_DIR)/libheapsentry.so
PY  := python3

LIB_SRCS  := $(wildcard $(LIB_DIR)/*.c)
LIB_OBJS  := $(LIB_SRCS:$(LIB_DIR)/%.c=$(BUILD_DIR)/%.o)

TARGETS_BIN := $(BUILD_DIR)/safe_demo $(BUILD_DIR)/realloc_demo \
               $(BUILD_DIR)/threaded_demo $(BUILD_DIR)/vulnerable_demo

TESTS_BIN := $(BUILD_DIR)/test_stress $(BUILD_DIR)/test_realloc \
             $(BUILD_DIR)/test_threads $(BUILD_DIR)/test_exhaustion

.PHONY: all library tests test check clean inspect-schema bench
.DEFAULT_GOAL := all

all: library tests

library: $(LIB)
tests: $(TARGETS_BIN) $(TESTS_BIN)

$(LIB): $(LIB_OBJS) | $(BUILD_DIR)
	$(CC) -shared $(CFLAGS) -o $@ $(LIB_OBJS) $(LD_FLAGS)

$(BUILD_DIR)/%.o: $(LIB_DIR)/%.c preload/internal.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(WARN) $(PIC) $(DEFS) -c -o $@ $<

$(BUILD_DIR)/%_demo: $(TARGET_DIR)/%_demo.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(WARN) $(DEFS) -o $@ $< $(LD_FLAGS)

# Stress tool: built from test_allocations.c (explicit rule).
$(BUILD_DIR)/test_stress: $(TEST_DIR)/test_allocations.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(WARN) $(DEFS) -o $@ $< $(LD_FLAGS)

# test_realloc / test_threads via pattern rule.
$(BUILD_DIR)/test_%: $(TEST_DIR)/test_%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(WARN) $(DEFS) -o $@ $< $(LD_FLAGS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR) $(LOGS_DIR)

# ---------------------------------------------------------------- tests
LOG_SAFE   := $(LOGS_DIR)/safe_demo.jsonl
LOG_REAL   := $(LOGS_DIR)/realloc_demo.jsonl
LOG_THREA  := $(LOGS_DIR)/threaded_demo.jsonl
LOG_STRESS := $(LOGS_DIR)/test_stress.jsonl
LOG_VULN   := $(LOGS_DIR)/vulnerable_demo.jsonl

PRELOAD = LD_PRELOAD=$(abspath $(LIB))

test: library tests
	@set -e; \
	mkdir -p $(BUILD_DIR) $(LOGS_DIR); \
	$(PRELOAD) HEAPSENTRY_LOG=$(LOG_SAFE)   $(BUILD_DIR)/safe_demo; \
	$(PRELOAD) HEAPSENTRY_LOG=$(LOG_REAL)   $(BUILD_DIR)/realloc_demo; \
	$(PRELOAD) HEAPSENTRY_LOG=$(LOG_THREA)  $(BUILD_DIR)/threaded_demo; \
	$(PRELOAD) HEAPSENTRY_LOG=$(LOG_STRESS) $(BUILD_DIR)/test_stress; \
	$(PRELOAD) HEAPSENTRY_LOG=$(BUILD_DIR)/test_realloc.jsonl $(BUILD_DIR)/test_realloc; \
	$(PRELOAD) HEAPSENTRY_LOG=$(BUILD_DIR)/test_threads.jsonl $(BUILD_DIR)/test_threads; \
	$(PRELOAD) HEAPSENTRY_TRACKED=64 \
	  HEAPSENTRY_LOG=$(BUILD_DIR)/test_exhaustion.jsonl $(BUILD_DIR)/test_exhaustion; \
	$(PY) $(TEST_DIR)/test_event_schema.py \
	      $(LOG_SAFE) $(LOG_REAL) $(LOG_THREA) $(LOG_STRESS) \
	      $(BUILD_DIR)/test_realloc.jsonl $(BUILD_DIR)/test_threads.jsonl \
	      $(BUILD_DIR)/test_exhaustion.jsonl; \
	grep -q '"status":"untracked"' $(BUILD_DIR)/test_exhaustion.jsonl; \
	echo "make test PASSED"

check: test
	@set -e; \
	$(MAKE) --no-print-directory check-baseline; \
	$(MAKE) --no-print-directory check-logging-failures; \
	$(MAKE) --no-print-directory check-vulnerable; \
	echo "make check PASSED"

# Baseline vs instrumented comparison (Test E).
check-baseline: library tests
	@set -e; \
	$(BUILD_DIR)/safe_demo > $(BUILD_DIR)/baseline.out; \
	$(PRELOAD) HEAPSENTRY_LOG=$(BUILD_DIR)/base.jsonl \
	  $(BUILD_DIR)/safe_demo > $(BUILD_DIR)/inst.out; \
	cmp $(BUILD_DIR)/baseline.out $(BUILD_DIR)/inst.out; \
	grep -q "initialization" $(BUILD_DIR)/base.jsonl; \
	echo "baseline/instrumented outputs identical; instrumented run produced events"

# Invalid log destinations must not crash the target. The /dev/full case
# exercises the sticky write-failure path (open succeeds, writes fail).
check-logging-failures: library tests
	@set -e; \
	$(PRELOAD) HEAPSENTRY_LOG=$(BUILD_DIR)/no-such-dir/x.jsonl \
	  $(BUILD_DIR)/safe_demo > /dev/null; \
	touch $(BUILD_DIR)/readonly.jsonl; chmod 400 $(BUILD_DIR)/readonly.jsonl; \
	$(PRELOAD) HEAPSENTRY_LOG=$(BUILD_DIR)/readonly.jsonl \
	  $(BUILD_DIR)/safe_demo > /dev/null; \
	chmod 644 $(BUILD_DIR)/readonly.jsonl; \
	$(PRELOAD) HEAPSENTRY_LOG=/dev/full $(BUILD_DIR)/safe_demo > /dev/null; \
	echo "logging-failure cases did not disturb target execution"

# Controlled vulnerable target: observation only — this is NOT automatic
# vulnerability detection. Produces an event log for manual inspection.
check-vulnerable: library tests
	@set -e; \
	$(PRELOAD) HEAPSENTRY_LOG=$(LOG_VULN) $(BUILD_DIR)/vulnerable_demo \
	  > $(BUILD_DIR)/vuln.out 2> $(BUILD_DIR)/vuln.err || true; \
	$(PY) $(TEST_DIR)/test_event_schema.py $(LOG_VULN); \
	echo "vulnerable demo ran; events validated; see $(LOG_VULN)"

# ---------------------------------------------------------------- bench
# Repeatable overhead measurement: threaded_demo with/without libheapsentry.
# Reports wall time; write results to docs after real runs.
bench: library tests
	@set -e; \
	mkdir -p $(BUILD_DIR) $(LOGS_DIR); \
	for i in 1 2 3; do \
	  /usr/bin/time -f "uninstrumented run $$i: %e s" \
	    $(BUILD_DIR)/threaded_demo >/dev/null 2>$(BUILD_DIR)/bench.$$i.b; \
	  cat $(BUILD_DIR)/bench.$$i.b | tail -1; \
	  /usr/bin/time -f "instrumented run $$i: %e s" \
	    env LD_PRELOAD=$(abspath $(LIB)) \
	    HEAPSENTRY_LOG=$(LOGS_DIR)/bench.$$i.jsonl \
	    $(BUILD_DIR)/threaded_demo >/dev/null 2>$(BUILD_DIR)/bench.$$i.a; \
	  tail -1 $(BUILD_DIR)/bench.$$i.a; \
	done; \
	echo "event counts:"; wc -l $(LOGS_DIR)/bench.*.jsonl

# ---------------------------------------------------------------- misc
inspect-schema: $(LOG_SAFE)
	$(PY) $(TEST_DIR)/test_event_schema.py $(LOG_SAFE)

clean:
	rm -rf $(BUILD_DIR) $(LOGS_DIR)
