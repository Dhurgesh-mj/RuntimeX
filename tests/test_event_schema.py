#!/usr/bin/env python3
"""HeapSentry event-log validator (Person 1 test utility only).

Validates JSONL event logs produced by libheapsentry.so:
  * syntax: every line is a valid JSON object
  * structural conformance to shared/event_schema.json (built-in checks;
    uses jsonschema for full validation only if it is installed)
  * event_id uniqueness and monotonic increase
  * allocation identity consistency: a deallocation id must have been
    minted by a prior allocation/reallocation success; ids must not be
    minted twice without an intervening supersede/fail

Usage: test_event_schema.py LOG.jsonl [LOG2.jsonl ...]

This is a test utility, not a second analysis engine.
"""
import json
import sys

SCHEMA_VERSION = 1
EVENTS = {"allocation", "deallocation", "reallocation",
          "initialization", "logger_error"}
STATUSES = {"ok", "failed", "untracked"}

REQUIRED = ["schema_version", "event_id", "event", "allocation_id",
            "timestamp_ns", "process_id", "thread_id", "status"]


class ValidationFailure(Exception):
    pass


def check(cond, msg):
    if not cond:
        raise ValidationFailure(msg)


def check_record(rec, idx):
    check(isinstance(rec, dict), "line is not a JSON object")
    for f in REQUIRED:
        check(f in rec, "missing required field %r" % f)
    check(rec["schema_version"] == SCHEMA_VERSION, "bad schema_version")
    check(rec["event"] in EVENTS, "unknown event type %r" % rec["event"])
    check(rec["status"] in STATUSES, "unknown status %r" % rec["status"])
    for f in ["event_id", "timestamp_ns", "process_id", "thread_id"]:
        check(isinstance(rec[f], int), "%s must be an integer" % f)
    aid = rec["allocation_id"]
    check(aid is None or (isinstance(aid, int) and aid >= 1),
          "allocation_id must be null or a positive integer")
    for f in ("run_id", "batch_id"):
        if f in rec:
            check(rec[f] is None or
                  (isinstance(rec[f], str) and rec[f] != ""),
                  "%s must be null or a non-empty string" % f)

    ev = rec["event"]
    if ev == "allocation":
        check(aid is not None if rec["status"] == "ok" else aid is None,
              "allocation ok<->non-null id / failed<->null id required")
        check("size" in rec, "allocation event must carry size")
    elif ev == "deallocation":
        if rec["status"] == "ok":
            check(isinstance(aid, int) and aid >= 1,
                  "ok deallocation needs a positive allocation_id")
            check("old_size" in rec, "ok deallocation carries old_size")
        else:
            check(rec["status"] == "untracked",
                  "deallocation status must be ok or untracked")
            check(aid is None, "untracked deallocation: null allocation_id")
    elif ev == "reallocation":
        check("size" in rec, "reallocation event must carry size")
        if rec["status"] == "ok" and aid is None:
            # zero-size free semantics: size 0
            check(rec["size"] == 0,
                  "ok reallocation with null new id implies size==0")
    elif ev in ("initialization", "logger_error"):
        check(aid is None, "%s event must have null allocation_id" % ev)


def validate_log(path):
    """Validate one log; returns dict of summary counters."""
    minted = {}       # id -> 'allocation' | 'freed' (freed allows reuse?)
    prev_event_id = -1
    events = 0

    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValidationFailure(
                    "%s:%d invalid JSON: %s" % (path, lineno, e))
            try:
                check_record(rec, lineno)
            except ValidationFailure as e:
                raise ValidationFailure("%s:%d %s" % (path, lineno, e))

            eid = rec["event_id"]
            check(eid > prev_event_id,
                  "event_id not strictly increasing (%d after %d)"
                  % (eid, prev_event_id))
            prev_event_id = eid
            events += 1

            aid = rec["allocation_id"]
            ev = rec["event"]
            if ev == "allocation" and aid is not None:
                check(aid not in minted or minted[aid] == "freed",
                      "allocation id %d minted twice" % aid)
                minted[aid] = "allocation"
            elif ev == "reallocation":
                oid = rec.get("old_allocation_id")
                if rec["status"] == "ok" and aid is not None:
                    check(aid not in minted or minted[aid] == "freed",
                          "allocation id %d minted twice" % aid)
                    minted[aid] = "allocation"
                if oid is not None:
                    check(oid in minted and minted[oid] in
                          ("allocation", "superseded"),
                          "realloc references unknown old id %d" % oid)
                    minted[oid] = "superseded"
            elif ev == "deallocation" and aid is not None:
                check(aid in minted,
                      "freed id %d was never minted in this log" % aid)
                minted[aid] = "freed"

    return {"path": path, "events": events}


def validate_with_jsonschema(path):
    """Optional: full draft-2020-12 validation if jsonschema is installed."""
    try:
        import jsonschema  # noqa: F401
    except ImportError:
        return False
    import os
    import jsonschema
    schema_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "..", "shared", "event_schema.json")
    with open(schema_path, "r", encoding="utf-8") as fh:
        schema = json.load(fh)
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    validator = validator_cls(schema)
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            validator.validate(json.loads(line))
    return True


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    failures = 0
    for path in argv[1:]:
        try:
            info = validate_log(path)
            full = validate_with_jsonschema(path)
            print("PASS %s (%d events%s)"
                  % (info["path"], info["events"],
                     ", full jsonschema validation" if full else ""))
        except ValidationFailure as e:
            print("FAIL %s: %s" % (path, e))
            failures += 1
        except FileNotFoundError:
            print("FAIL %s: file not found" % path)
            failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
