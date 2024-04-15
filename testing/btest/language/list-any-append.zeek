# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

function append(l: list of any)
	{
	l += |l|;
	}

type R: record { r: string &default="r"; };
type S: record { s: string &default="s"; };

global q: list of any;

function keep_this_two_ways(r: any)
	{
	q += r;
	q += r;
	}

event zeek_init()
	{
	local l: list of count;
	append(l);
	append(l);
	print l;

	local l2: list of any;
	l2 += |l|;
	l2 += l;
	print l2;

	local l3: list of any;
	local l4: any = list(4, 5);

	l3 += 1;
	l3 += list(2, 3);
	l3 += l4;

	print l3, |l3|;
	for ( ll in l3 )
		print ll, type_name(ll);

	keep_this_two_ways(R());
	keep_this_two_ways(S());
	print q;

	local l5: list of any;
	local l6: list of any;

	l5 += "a";
	l5 += -3;

	l6 += l5;
	print l6;

	local l7: list of count;
	l7 = --l3;
	print l7;

	local l8 = --l3;
	print l8;

	l7 = --l3;
	print l7, l3;
	}
