# @TEST-EXEC: btest-bg-run bro bro -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff bro/.stdout
# @TEST-EXEC: btest-diff bro/.stderr

@TEST-START-FILE input.log
#fields	i	p
1.2.3.4	80/tcp
1.2.3.5	52/udp
1.2.3.6	30/unknown
1.2.3.7	50/trash
@TEST-END-FILE

redef exit_only_after_terminate = T;

redef InputAscii::empty_field = "EMPTY";

module A;

type Idx: record {
	i: addr;
};

type Val: record {
	p: port;
};

global servers: table[addr] of Val = table();

event line(description: Input::TableDescription, tpe: Input::Event, left: Idx, right: Val)
	{
	print left, right;
	}

event bro_init()
	{
	Input::add_table([$source="../input.log", $name="input", $idx=Idx, $val=Val, $ev=line, $destination=servers]);
	}

event Input::end_of_data(name: string, source: string)
	{
	Input::remove("input");
	terminate();
	}
