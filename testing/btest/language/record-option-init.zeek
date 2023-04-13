# Ensures that an error is printed out for option variables
# that are containers if they aren't initialized.

# @TEST-EXEC-FAIL: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out

@load misc/stats

type TestRecord: record {
	a: count;
	b: Stats::Info &optional;
};

option foo: TestRecord &redef;

event zeek_init()
	{
	print foo;
	}
