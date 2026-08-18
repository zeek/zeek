# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: btest-diff-remove-abspath out

type r: record {
	v: vector of int;
};

event zeek_init()
	{
	local l = r($v=vector());
	l$v[1] = 9;
	print l$v;
	}
