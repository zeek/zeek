#
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

@TEST-START-FILE input.log
#separator \x09
#path	ssh
#fields	i	b	
#types	int	bool
1	T
2	T
3	F
4	F
5	F
6	F
7	T
@TEST-END-FILE


module A;

export {
	redef enum Input::ID += { INPUT };
}

type Val: record {
	i: int;
	b: bool;
};

event line(tpe: Input::Event, i: int, b: bool) {
	print tpe;
	print i;
	print b;
}

event bro_init()
{
	Input::create_stream(A::INPUT, [$source="input.log"]);
	Input::add_eventfilter(A::INPUT, [$name="input", $fields=Val, $ev=line]);
}
