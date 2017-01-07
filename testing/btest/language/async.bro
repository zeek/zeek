# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

function x() : string
	{
	print "in x";
	return "x-return";
	}

function bar()
	{
	print "=== bar()";
	
	local i = 0;

	# An expression with a side effect to make sure it's not evaluated
	# multiple times.
	print fmt("Q1: i=%d h=%s x=%s", ++i, async lookup_addr(131.159.14.23), x());
	print fmt("Q2: i=%d", i);
	}

function foo()
	{
	print "=== foo()";
	
	local a: string;

	print "  X";
	
	a = async lookup_addr(131.159.14.1);
	
	print "  Y", a;
	
	a = async lookup_addr(8.8.8.8);
	
	print "  Z", a;

	bar();
	}

event bro_init()
	{
	local ips: set[addr];

	print "A";
	
	ips = async lookup_hostname("www.icir.org");
	
	print "B", ips;
	
	ips = async lookup_hostname("www.bro.org");
	
	print "C", ips;

	foo();

	print "D";
	}

event bro_init() &priority=-500
	{
	print "PRIO -500";
	}

event bro_init() &priority=500
	{
	print "PRIO +500";
	}
