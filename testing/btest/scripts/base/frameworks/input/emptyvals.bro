#
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

@TEST-START-FILE input.log
#separator \x09
#path	ssh
#fields	b	i
##types	bool	int
T	1
-	2
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
	# first read in the old stuff into the table...
	Input::add_table([$source="input.log", $name="ssh", $idx=Idx, $val=Val, $destination=servers]);
	Input::remove("ssh");
}

event Input::update_finished(name: string, source:string) {
	print servers;
}
