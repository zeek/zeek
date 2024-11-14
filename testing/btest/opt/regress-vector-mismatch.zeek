# @TEST-DOC: Regression test for coercing vectors-of-any
# @TEST-EXEC: zeek -b -O ZAM %INPUT >output
# @TEST-EXEC: btest-diff output

module X;

export {
	option o: vector of string = vector();
}

event zeek_init()
	{
	local x: any = vector();
	Config::set_value("X::o", vector("a") + (x as vector of string));
	print X::o;
	print x;
	}
