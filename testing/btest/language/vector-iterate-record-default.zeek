# @TEST-DOC: Iterating over vectors holding record. This mirrors table-iterate-record-key-default, but for vectors. They didn't have the same issue. Regression test for #3267.
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

global vec: vector of R;

print seq, "populating vector, expecting 4 my_seq() invocations";
vec += R();
vec += R();
vec += R();
vec += R();

print seq, "iterating vector, expecting no my_seq() invocations";
for ( i, r in vec )
	print seq, "it", i, r;

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

global vec: vector of R;

event zeek_init()
	{
	print seq, "populating vector, expecting 4 my_seq() invocations";
	vec += R();
	vec += R();
	vec += R();
	vec += R();

	print seq, "iterating vector, expecting no my_seq() invocations";
	for ( i, r in vec )
		print seq, "it", i, r;

	print seq, "done";
	}

print seq, "done parsing";
