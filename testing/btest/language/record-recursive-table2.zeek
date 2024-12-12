# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

type Foo: record {
	id: string;
};

redef record Foo += {
	foo: Foo &optional;
};

event zeek_init()
	{
	local tbl: table[Foo] of Foo;
	local f1 = Foo($id="1");
	local f2 = Foo($id="2", $foo=f1);
	print "===", |tbl|, tbl;
	tbl[f1] = f2;
	print "===", |tbl|, tbl;
	}
