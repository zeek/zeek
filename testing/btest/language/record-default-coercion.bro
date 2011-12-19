# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

type MyRecord: record {
	a: count &default=13;
	c: count;
	v: vector of string &default=vector();
};

event bro_init()
	{
	local r: MyRecord = [$c=13];
	print r;
	print |r$v|;
	r$v[|r$v|] = "test";
	print r;
	print |r$v|;
	}
