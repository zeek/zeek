# @TEST-DOC: Bad &default_insert usage.
#
# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

# Not applicable to record fields.
type R: record {
	a: string &default_insert="a";
};

# @TEST-START-NEXT
# Not applicable to sets.
global s: set[string] &default_insert="a";

# @TEST-START-NEXT
# Wrong expression type
global tbl: table[count] of string &default_insert=1;

# @TEST-START-NEXT

# default function has wrong type
global tbl: table[count] of string &default_insert=function(c: count): count { return c; };

# @TEST-START-NEXT

# default function has wrong type for inferred type
global tbl = table([1] = "a") &default_insert=function(c: count): count { return c; };

# @TEST-START-NEXT

# Using &default and &default_insert together does not work.
global tbl: table[count] of string &default="a" &default_insert="b";

# @TEST-START-NEXT
# Using &default and &default_insert together does not work, reversed order.
global tbl: table[count] of string &default_insert="a" &default="b";
