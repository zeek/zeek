#
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

@TEST-START-FILE input.log
#fields	i	p	t
1.2.3.4	80	tcp
1.2.3.5	52	udp
1.2.3.6	30	unknown
@TEST-END-FILE

redef InputAscii::empty_field = "EMPTY";

module A;

export {
	redef enum Input::ID += { INPUT };
}

type Idx: record {
	i: addr;
};

type Val: record {
	p: port &type_column="t";
};

global servers: table[addr] of Val = table();

event bro_init()
{
	# first read in the old stuff into the table...
	Input::create_stream(A::INPUT, [$source="input.log"]);
	Input::add_tablefilter(A::INPUT, [$name="input", $idx=Idx, $val=Val, $destination=servers]);
	Input::force_update(A::INPUT);
	print servers[1.2.3.4];
	print servers[1.2.3.5];
	print servers[1.2.3.6];
	Input::remove_tablefilter(A::INPUT, "input");
	Input::remove_stream(A::INPUT);
}
