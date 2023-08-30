# @TEST-DOC: Deferred initialization at parse time fairly nested.
# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT >output
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

global s1 = State();
global s2 = State();
global os1 = OtherState();
global os2 = OtherState();

redef record InnerMost += {
	seq: count &default=my_seq();
};

# seq of Inner are initialized *after* InnerMost$seq.
redef record Inner += {
	seq: count &default=my_seq();
};

print seq, "printing";

print seq, "s1", s1;
print seq, "s2", s2;
print seq, "os1", os1;
print seq, "os2", os2;
