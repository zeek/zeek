#
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out

type MyRec: record {
	a: count &optional;
	b: count;
};

type MyTable: table[MyRec] of string;

event zeek_init()
	{
	local t1 = table(
		["http"] = "http://www.google.com/",
		["https"] = "https://www.google.com/");
	local t2 = MyTable([[$a=10, $b=5]] = "b5", [[$b=7]] = "b7");
	local t3: table[port, string, bool] of string = table(
			 [1/tcp, "test", T] = "test1",
			 [2/tcp, "example", F] = "test2");

	local v1: set[string] = table_keys(t1);
	local v2: set[MyRec] = table_keys(t2);
	local v3: set[port, string, bool] = table_keys(t3);

	print v1;
	print v2;
	print v3;
	}
