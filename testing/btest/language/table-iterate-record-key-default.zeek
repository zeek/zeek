# @TEST-DOC: Iterating over tables with record keys would previously evaluate &default during each iteration. Ensure this isn't happening. Regression test for #3267.
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

global tbl: table[R] of count;

print seq, "populating table, expecting 4 my_seq() invocations";

tbl[R()] = 1;
tbl[R()] = 2;
tbl[R()] = 3;
tbl[R()] = 4;

print seq, "iterating table, expecting no my_seq() invocations";
for ( [r], c in tbl )
	print seq, "it", r, c;

print seq, "done";

# @TEST-START-NEXT
#
# This acts subtly different - my_seq() is called maybe for the [r] local
# in the for loop?!
global seq = 0;
function my_seq(): count {
	print seq, "my_seq() invoked";
	return ++seq;
}

type R: record {
	id: count &default=my_seq();
};

global tbl: table[R] of count;

 event zeek_init()
	{
	print seq, "populating table, expecting 4 my_seq() invocations";

	tbl[R()] = 1;
	tbl[R()] = 2;
	tbl[R()] = 3;
	tbl[R()] = 4;

	print seq, "iterating table, expecting no my_seq() invocations";
	for ( [r], c in tbl )
		print seq, "it", r, c;

	print seq, "done";
	}

print seq, "done parsing";

# @TEST-START-NEXT
#
# table[R] of R
global seq = 0;
function my_seq(): count {
	print seq, "my_seq() invoked";
	return ++seq;
}

type R: record {
	id: count &default=my_seq();
};

global tbl: table[R] of R;

 event zeek_init()
	{
	print seq, "populating table, expecting 8 my_seq() invocations";

	tbl[R()] = R();
	tbl[R()] = R();
	tbl[R()] = R();
	tbl[R()] = R();

	print seq, "iterating table, expecting no my_seq() invocations";
	for ( [r1], r2 in tbl )
		print seq, "it", r1, r2;

	print seq, "done";
	}

print seq, "done parsing";
