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

type Idx: record {
	i: int;
};

type Val: record {
	b: bool;
};

global destination: table[int] of Val = table();

event line(description: Input::TableDescription, tpe: Input::Event, left: Idx, right: bool) {
	print description;
	print tpe;
	print left;
	print right;
}

event bro_init()
{
	Input::add_table([$source="input.log", $name="input", $idx=Idx, $val=Val, $destination=destination, $want_record=F,$ev=line]);
	Input::remove("input");
}
