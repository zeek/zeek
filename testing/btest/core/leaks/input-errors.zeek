# Needs perftools support.
# Test different kinds of errors of the input framework
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -m -b %INPUT
# @TEST-EXEC: btest-bg-wait 60

@TEST-START-FILE input.log
#separator \x09
#path	ssh
#fields	b	i	e	c	p	sn	a	d	t	iv	s	sc	ss	se	vc	ve	ns
#types	bool	int	enum	count	port	subnet	addr	double	time	interval	string	table	table	table	vector	vector	string
T	-42	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	4242
@TEST-END-FILE

redef Input::accept_unsupported_types = T;

redef exit_only_after_terminate = T;

module Test;

global outfile: file;

type Idx: record {
	c: count;
};

type Idx2: record {
	c: count;
	i: int;
};

type FileVal: record {
	i: int;
	s: file;
};

type Val: record {
	i: int;
	s: string;
	a: addr;
};

type OptionalRecordVal: record {
	i: int;
	r: FileVal &optional;
};

type OptionalFileVal: record {
	i: int;
	s: file &optional;
};

global file_table: table[count] of FileVal = table();
global optional_file_table: table[count] of OptionalFileVal = table();
global record_table: table[count] of OptionalRecordVal = table();
global string_table: table[string] of OptionalRecordVal = table();

global val_table: table[count] of Val = table();
global val_table2: table[count, int] of Val = table();
global val_table3: table[count, int] of int = table();
global val_table4: table[count] of int;

event line_file(description: Input::EventDescription, tpe: Input::Event, r:FileVal)
	{
	print outfile, description$name;
	print outfile, r;
	}

event optional_line_file(description: Input::EventDescription, tpe: Input::Event, r:OptionalFileVal)
	{
	print outfile, description$name;
	print outfile, r;
	}

event line_record(description: Input::EventDescription, tpe: Input::Event, r: OptionalRecordVal)
	{
	print outfile, description$name;
	print outfile, r;
	}

event event1(description: Input::EventDescription, tpe: Input::Event, r: OptionalRecordVal, r2: OptionalRecordVal)
	{
	}

event event2(description: Input::TableDescription, tpe: string, r: OptionalRecordVal, r2: OptionalRecordVal)
	{
	}

event event3(description: Input::TableDescription, tpe: Input::Event, r: OptionalRecordVal, r2: OptionalRecordVal)
	{
	}

event event4(description: Input::TableDescription, tpe: Input::Event, r: Idx, r2: OptionalRecordVal)
	{
	}

event event5(description: Input::EventDescription, tpe: string, r: OptionalRecordVal, r2: OptionalRecordVal)
	{
	}

event event6(description: Input::EventDescription, tpe: Input::Event, r: OptionalRecordVal)
	{
	}

event event7(description: Input::EventDescription, tpe: Input::Event, r: OptionalRecordVal, r2:OptionalRecordVal)
	{
	}

event event8(description: Input::EventDescription, tpe: Input::Event, i: int, s:string, a:string)
	{
	}

event event9(description: Input::EventDescription, tpe: Input::Event, i: int, s:string, a:addr, ii: int)
	{
	}

event event10(description: Input::TableDescription, tpe: Input::Event, i: Idx, c: count)
	{
	}

# these are legit to test the error events
event event11(description: Input::EventDescription, tpe: Input::Event, v: Val)
	{
	}

event errorhandler1(desc: Input::TableDescription, msg: string, level: Reporter::Level)
	{
	}

event errorhandler2(desc: Input::EventDescription, msg: string, level: Reporter::Level)
	{
	}

event errorhandler3(desc: string, msg: string, level: Reporter::Level)
	{
	}

event errorhandler4(desc: Input::EventDescription, msg: count, level: Reporter::Level)
	{
	}

event errorhandler5(desc: Input::EventDescription, msg: string, level: count)
	{
	}

event kill_me()
	{
	terminate();
	}

event zeek_init()
	{
	outfile = open("out");
	Input::add_event([$source="input.log", $name="file", $fields=FileVal, $ev=line_file, $want_record=T]);
	Input::add_event([$source="input.log", $name="optionalrecord", $fields=OptionalRecordVal, $ev=line_record, $want_record=T]);
	Input::add_event([$source="input.log", $name="optionalfile", $fields=OptionalFileVal, $ev=optional_line_file, $want_record=T]);
	Input::add_table([$source="input.log", $name="filetable", $idx=Idx, $val=FileVal, $destination=file_table]);
	Input::add_table([$source="input.log", $name="optionalrecordtable", $idx=Idx, $val=OptionalRecordVal, $destination=record_table]);
	Input::add_table([$source="input.log", $name="optionalfiletable", $idx=Idx, $val=OptionalFileVal, $destination=optional_file_table]);
	Input::add_table([$source="input.log", $name="optionalfiletable", $idx=Idx, $val=OptionalFileVal, $destination=record_table]);
	Input::add_table([$source="input.log", $name="optionalfiletable2", $idx=Idx, $val=OptionalFileVal, $destination=string_table]);
	Input::add_table([$source="input.log", $name="optionalfiletable3", $idx=Idx, $val=OptionalFileVal, $destination=optional_file_table, $ev=terminate]);
	Input::add_table([$source="input.log", $name="optionalfiletable3", $idx=Idx, $val=OptionalFileVal, $destination=optional_file_table, $ev=kill_me]);
	Input::add_table([$source="input.log", $name="optionalfiletable4", $idx=Idx, $val=OptionalFileVal, $destination=optional_file_table, $ev=event1]);
	Input::add_table([$source="input.log", $name="optionalfiletable5", $idx=Idx, $val=OptionalFileVal, $destination=optional_file_table, $ev=event2]);
	Input::add_table([$source="input.log", $name="optionalfiletable6", $idx=Idx, $val=OptionalFileVal, $destination=optional_file_table, $ev=event3]);
	Input::add_table([$source="input.log", $name="optionalfiletable7", $idx=Idx, $val=OptionalFileVal, $destination=optional_file_table, $ev=event4]);
	Input::add_table([$source="input.log", $name="optionalfiletable8", $idx=Idx, $val=Val, $destination=val_table4, $want_record=F]);
	Input::add_table([$source="input.log", $name="optionalfiletable9", $idx=Idx2, $val=Val, $destination=val_table, $want_record=F]);
	Input::add_table([$source="input.log", $name="optionalfiletable10", $idx=Idx, $val=Val, $destination=val_table2, $want_record=F]);
	Input::add_table([$source="input.log", $name="optionalfiletable11", $idx=Idx2, $val=Idx, $destination=val_table3, $want_record=F]);
	Input::add_table([$source="input.log", $name="optionalfiletable12", $idx=Idx2, $val=Idx, $destination=val_table2, $want_record=F]);
	Input::add_table([$source="input.log", $name="optionalfiletable14", $idx=Idx, $val=OptionalFileVal, $destination=optional_file_table, $ev=event10, $want_record=F]);
	Input::add_table([$source="input.log", $name="optionalfiletable15", $idx=Idx2, $val=Idx, $destination=val_table2, $want_record=T]);
	Input::add_event([$source="input.log", $name="event1", $fields=OptionalFileVal, $ev=terminate, $want_record=T]);
	Input::add_event([$source="input.log", $name="event2", $fields=OptionalFileVal, $ev=kill_me, $want_record=T]);
	Input::add_event([$source="input.log", $name="event3", $fields=OptionalFileVal, $ev=event3, $want_record=T]);
	Input::add_event([$source="input.log", $name="event4", $fields=OptionalFileVal, $ev=event5, $want_record=T]);
	Input::add_event([$source="input.log", $name="event5", $fields=OptionalFileVal, $ev=event6, $want_record=T]);
	Input::add_event([$source="input.log", $name="event6", $fields=OptionalFileVal, $ev=event7, $want_record=T]);
	Input::add_event([$source="input.log", $name="event7", $fields=OptionalFileVal, $ev=event7, $want_record=F]);
	Input::add_event([$source="input.log", $name="event8", $fields=Val, $ev=event8, $want_record=F]);
	Input::add_event([$source="input.log", $name="event9", $fields=Val, $ev=event9, $want_record=F]);

	Input::add_event([$source="input.log", $name="error1", $fields=Val, $ev=event11, $want_record=T, $error_ev=errorhandler1]);
	Input::add_table([$source="input.log", $name="error2", $idx=Idx, $val=Val, $destination=val_table, $error_ev=errorhandler2]);
	Input::add_event([$source="input.log", $name="error3", $fields=Val, $ev=event11, $want_record=T, $error_ev=errorhandler3]);
	Input::add_event([$source="input.log", $name="error4", $fields=Val, $ev=event11, $want_record=T, $error_ev=errorhandler4]);
	Input::add_event([$source="input.log", $name="error5", $fields=Val, $ev=event11, $want_record=T, $error_ev=errorhandler5]);

	schedule 3secs { kill_me() };
	}
