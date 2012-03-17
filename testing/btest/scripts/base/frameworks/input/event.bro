#
# @TEST-EXEC: bro -b %INPUT >out
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

type Val: record {
	i: int;
	b: bool;
};

event line(description: Input::EventDescription, tpe: Input::Event, i: int, b: bool) {
	print description;
	print tpe;
	print i;
	print b;
}

event bro_init()
{
	Input::add_event([$source="input.log", $name="input", $fields=Val, $ev=line]);
	Input::remove("input");
}
