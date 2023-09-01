# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

function assign(v: vector of any)
	{
	v[|v|] = |v|;
	}

function append(v: vector of any)
	{
	v += |v|;
	}

type R: record { r: string &default="r"; };
type S: record { s: string &default="s"; };

global q: vector of any;

function keep_this_two_ways(r: any)
	{
	q += r;
	q[|q|] = r;
	}

event zeek_init()
	{
	local v: vector of count;
	assign(v);
	assign(v);
	append(v);
	append(v);
	print v;

	local v2: vector of any;
	v2 += |v|;
	v2 += v;
	print v2;

	local v3: vector of any;
	local v4: any = vector(4, 5);

	v3 += 1;
	v3 += vector(2, 3);
	v3 += v4;

	print v3, |v3|, type_name(v3[0]), type_name(v3[1]), type_name(v3[3]);

	keep_this_two_ways(R());
	keep_this_two_ways(S());
	print q;

	local v5: vector of any;
	local v6: vector of any;
	local v7: vector of count;

	v5 += "a";
	v5 += -3;

	v6 += v5;
	print v6;

	v7 += v5;
	print v7;
	}
