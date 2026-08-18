# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff-remove-abspath output

type X: record  {
    a: addr;
    b: port;
};

event zeek_init()
	{
	local x: X;
	x = [$a = 1.2.3.4, $b=1947/tcp];

	local s = "sTriNg" as string;
	local y = x as X;

	print s, s is string;
	print y, y is X;
	}


