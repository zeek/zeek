# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

# @TEST-DOC: Test for type-checking of `in` operator.

type MyRec: record {
	a: count &default=1;
};

local myrec = MyRec();
local strings: set[string] = set();
local records: set[MyRec] = set();
local string_counts: set[string, count] = set();
local string_records: set[string, MyRec] = set();
local record_strings: set[MyRec, string] = set();

# These are all valid.
["asdf"] in strings;
["hi", 0] in string_counts;
myrec in records;
[myrec] in records;
MyRec() in records;
[$a = 2] in records;
[MyRec()] in records;
[[$a = 2]] in records;
["hi", myrec] in string_records;

# All below should fail type-checking.

myrec in "asdf";
myrec in string_records;
myrec in record_strings;
