# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

global a: table[count] of count &default = 10 &default = 9;
global b: table[count] of count &deprecated &deprecated;
global c: table[count] of count &deprecated="a" &deprecated;
global d: table[count] of count &deprecated &deprecated="a";
global e: table[count] of count &redef &redef;
