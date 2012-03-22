#
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

@TEST-START-FILE input.log
#separator \x09
#path	ssh
#fields	b	i	
#types	bool	int
T	-42	
@TEST-END-FILE

redef InputAscii::empty_field = "EMPTY";

module A;

type Idx: record {
	i: int;
};

type Val: record {
	b: bool;
};

global servers: table[int] of Val = table();

event bro_init()
{
	Input::add_table([$name="input", $source="input.log", $idx=Idx, $val=Val, $destination=servers]);
	Input::remove("input");
}

event Input::update_finished(name: string, source: string) {
	print servers;
}

