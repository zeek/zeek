# @TEST-EXEC-FAIL: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

global s: set[string] &create_expire=1secs &read_expire=1secs;

# @TEST-START-NEXT:

global s: set[string] &write_expire=1secs &create_expire=3secs;

# @TEST-START-NEXT:

global s: set[string] &write_expire=1secs &read_expire=3secs;
