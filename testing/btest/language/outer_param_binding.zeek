# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

type Foo: record {
	x: function(a: string) : string;
};

function bar(b: string, c: string)
	{
	local f: Foo;
	local d = 8;
	f = [$x=function(a: string) : string
			{
			local x = 0;
			print x;
			print c, d;
			return cat(a, " ", b);
			}
		];

	print f$x("2");
	}

event zeek_init()
	{
	bar("1", "20");
	}
