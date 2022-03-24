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
print ["asdf"] in strings;
print ["hi", 0] in string_counts;
print myrec in records;
print [myrec] in records;
print MyRec() in records;
print [$a = 2] in records;
print [MyRec()] in records;
print [[$a = 2]] in records;
print ["hi", myrec] in string_records;

# All below should fail type-checking.

print myrec in "asdf";
print myrec in string_records;
print myrec in record_strings;

# Patterns do not apply transparently to collections of strings, so fail
# to type-check too:

print /foo/ in strings;

# Complex index types need to match, too. (For tests with matching types,
# see set.zeek / table.zeek.)

local table_set: set[table[string] of string] = set();
local stringvec_set: set[vector of string] = set();
local string_count_map: table[string] of count = table();

print string_count_map in table_set;
print vector(1, 2, 3) in stringvec_set;
