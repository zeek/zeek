# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type myrec: record {
	foo: function(a: string);
};

event zeek_init()
	{
	local w = "world";
	local mr = myrec($foo[w](a: string) = { print a + w; });
	mr$foo("hello");
	}
