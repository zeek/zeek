#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

@TEST-START-FILE input.log
#fields	i	p	t
1.2.3.4	80	tcp
1.2.3.5	52	udp
1.2.3.6	30	unknown
@TEST-END-FILE

redef InputAscii::empty_field = "EMPTY";

module A;

type Idx: record {
	i: addr;
};

type Val: record {
	p: port &type_column="t";
};

global servers: table[addr] of Val = table();

event bro_init()
{
	Input::add_table([$source="input.log", $name="input", $idx=Idx, $val=Val, $destination=servers]);
	print servers[1.2.3.4];
	print servers[1.2.3.5];
	print servers[1.2.3.6];
	Input::remove("input");
}

event Input::update_finished(name: string, source: string) {
	print servers[1.2.3.4];
	print servers[1.2.3.5];
	print servers[1.2.3.6];
}

