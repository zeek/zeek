# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

function assign(v: vector of any)
	{
	v[|v|] = |v|;
	}

function append(v: vector of any)
	{
	v += |v|;
	}

event bro_init()
	{
	local v: vector of count;
	assign(v);
	assign(v);
	append(v);
	append(v);
	print v;
	}
