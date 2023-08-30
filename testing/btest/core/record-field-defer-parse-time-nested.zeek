# @TEST-DOC: Test deferred initialization behavior for nested records and redef.
# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: TEST_DIF_CANONIFIER= btest-diff output

module Test;

global seq = 0;

function my_seq(): count {
	print seq, "my_seq()";
	return ++seq;
}

type InnerMost: record { };

type Inner: record {
	inner_most: InnerMost;
};

type State: record {
	seq: count &default=my_seq();
	inner: Inner;
};

type OtherState: record {
	inner_most: InnerMost;
};

# s1$seq and s2$seq receive 1, 2
global s1 = State();
global s2 = State();
global os1 = OtherState();
global os2 = OtherState();

# This uses up seq 3,4,5,6 for nested InnerMost in s1,s2,os1,os2.
redef record InnerMost += {
	seq: count &default=my_seq();
};

# This uses seq 7, 8 for s1 and s2.
redef record Inner += {
	seq: count &default=my_seq();
};

print seq, "printing";

print seq, "s1", s1;
print seq, "s2", s2;
print seq, "os1", os1;
print seq, "os2", os2;
