# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: btest-diff-remove-abspath out

# Record ctor's expression list shouldn't accept "expressions that
# eval into record".  The expression list should only be comprised of
# record-field-assignment expressions.

type myrec: record {
	cmd: string;
	stdin: string &default="";
	read_files: string &optional;
};

local bad = myrec([$cmd="echo hi"]);

print bad;
