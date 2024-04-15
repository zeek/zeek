# @TEST-DOC: Iterating over lists holding record. This mirrors table-iterate-record-key-default, but for lists. They didn't have the same issue. Regression test for #3267.
# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

global seq = 0;
function my_seq(): count {
	print seq, "my_seq() invoked";
	return ++seq;
}

type R: record {
	id: count &default=my_seq();
};

global l: list of R;

print seq, "populating list, expecting 4 my_seq() invocations";
l += R();
l += R();
l += R();
l += R();

print seq, "iterating list, expecting no my_seq() invocations";
for ( r in l )
	print seq, "it", r;

print seq, "done";

# @TEST-START-NEXT
#
# Same as above, but populate / iterate record in zeek_init.
global seq = 0;
function my_seq(): count {
	print seq, "my_seq() invoked";
	return ++seq;
}

type R: record {
	id: count &default=my_seq();
};

global l: list of R;

event zeek_init()
	{
	print seq, "populating list, expecting 4 my_seq() invocations";
	l += R();
	l += R();
	l += R();
	l += R();

	print seq, "iterating list, expecting no my_seq() invocations";
	for ( r in l )
		print seq, "it", r;

	print seq, "done";
	}

print seq, "done parsing";
