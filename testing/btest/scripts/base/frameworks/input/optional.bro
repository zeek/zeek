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

redef InputAscii::empty_field = "EMPTY";

module A;

type Idx: record {
	i: int;
};

type Val: record {
	b: bool;
	notb: bool &optional;
};

global servers: table[int] of Val = table();

event bro_init()
{
	# first read in the old stuff into the table...
	Input::add_table([$source="input.log", $name="input", $idx=Idx, $val=Val, $destination=servers, 
				$pred(typ: Input::Event, left: Idx, right: Val) = { right$notb = !right$b; return T; }
				]);
	Input::remove("input");
}

event Input::update_finished(name: string, source: string) {
	print servers;
}
