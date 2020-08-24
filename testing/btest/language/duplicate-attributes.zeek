# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

global a: table[count] of count
        &default = 10 &default = 9
        &read_expire = 5 sec &read_expire = 1 min;
