# @TEST-DOC: Deferred initialization at parse time.
# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT >output
# @TEST-EXEC: TEST_DIF_CANONIFIER= btest-diff output

module Test;

global seq = 0;

function my_seq(): count {
	print seq, "my_seq()";
	return ++seq;
}

type Inner: record { };

type State: record {
	seq: count &default=my_seq();
	inner: Inner;
};

redef record Inner += {
	seq: count &default=my_seq();
};

global tbl: table[State] of State;

global s1 = State();
global s2 = State();

tbl[s1] = s1;
tbl[s2] = s2;

print seq, "printing";
print seq, "s1", s1;
print seq, "s2", s2;
print seq, "tbl", tbl;
print seq, "done";

# @TEST-START-NEXT

# Same as before, but redef after creating globals.
#
#
module Test;

global seq = 0;

function my_seq(): count {
	print seq, "my_seq()";
	return ++seq;
}

type Inner: record { };

type State: record {
	seq: count &default=my_seq();
	inner: Inner;
};

global tbl: table[State] of State;

global s1 = State();
global s2 = State();

redef record Inner += {
	seq: count &default=my_seq();
};

tbl[s1] = s1;
tbl[s2] = s2;

print seq, "printing";
print seq, "s1", s1;
print seq, "s2", s2;
print seq, "tbl", tbl;
print seq, "done";

# @TEST-START-NEXT

# Same as before, but in zeek_init() with locals.
#
#
module Test;

global seq = 0;

function my_seq(): count {
	print seq, "my_seq()";
	return ++seq;
}

type Inner: record { };

type State: record {
	seq: count &default=my_seq();
	inner: Inner;
};

redef record Inner += {
	seq: count &default=my_seq();
};

event zeek_init()
	{
	local tbl: table[State] of State;
	local s1 = State();
	local s2 = State();
	tbl[s1] = s1;
	tbl[s2] = s2;
	print seq, "printing";
	print seq, "s1", s1;
	print seq, "s2", s2;
	print seq, "tbl", tbl;
	print seq, "done";
	}
