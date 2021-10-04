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

# Patterns do not apply transparently to collections of strings, so fail
# to type-check too:

/foo/ in strings;

# Complex index types need to match, too. (For tests with matching types,
# see set.zeek / table.zeek.)

local table_set: set[table[string] of string] = set();
local stringvec_set: set[vector of string] = set();
local string_count_map: table[string] of count = table();

string_count_map in table_set;
vector(1, 2, 3) in stringvec_set;
