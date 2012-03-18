#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

@TEST-START-FILE input.log
#separator \x09
#path	ssh
#fields	i	b	
#types	int	bool
1	T
@TEST-END-FILE

redef InputAscii::empty_field = "EMPTY";

module A;

type Idx: record {
	i: int;
};

type Val: record {
	b: bool;
};

global destination: table[int] of Val = table();

const one_to_32: vector of count = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};

event bro_init()
{
	for ( i in one_to_32 ) {
		Input::add_table([$source="input.log", $name=fmt("input%d", i), $idx=Idx, $val=Val, $destination=destination, $want_record=F]);
		Input::remove(fmt("input%d", i));
	}
}

event Input::update_finished(name: string, source: string) {
	print name;
	print source;
	print destination;
}
