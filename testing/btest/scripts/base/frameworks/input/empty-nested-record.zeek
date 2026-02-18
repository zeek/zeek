# @TEST-DOC: Check that empty record types are ignored.
# TODO: This test hangs indefinitely on Windows and is skipped for the time being.
# @TEST-REQUIRES: ! is-windows
#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff .stderr
# @TEST-EXEC: btest-diff out

# @TEST-START-FILE input.log
#separator \x09
#path	ssh
#fields	s	r0.c0	r0.c1	r0.s
#types	string	count	string
string1	4242	4711	r0s-1
string2	4343	-	r0s-2
# @TEST-END-FILE

redef exit_only_after_terminate = T;

module Test;

type EmptyRec: record { };

type MyRec: record {
	e0: EmptyRec;  # stuffing
	c0: count;
	c1: count &optional;
	e1: EmptyRec;  # stuffing
	s: string;
};

type Val: record {
	s: string;
	e0: EmptyRec;  # stuffing
	r0: MyRec;
	e1: EmptyRec;  # stuffing
};

event Test::line(description: Input::EventDescription, tpe: Input::Event, v: Val)
	{
	print tpe, v;
	}

event Input::end_of_data(name: string, source:string)
	{
	terminate();
	}

event zeek_init()
	{
	Input::add_event([$source="input.log", $name="file", $fields=Val, $ev=Test::line]);
	}
