# @TEST-DOC: Test deferred initialization behavior at parse time.
# @TEST-EXEC: zeek -b %INPUT >output
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

global s1 = State();
global s2 = State();

redef record Inner += {
	seq: count &default=my_seq();
};

print seq, "printing";

print seq, "s1", s1;
print seq, "s2", s2;
