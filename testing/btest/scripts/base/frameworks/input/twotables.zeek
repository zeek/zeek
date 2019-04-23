# @TEST-EXEC: mv input1.log input.log
# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/got2 5 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: mv input3.log input.log
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff event.out
# @TEST-EXEC: btest-diff pred1.out
# @TEST-EXEC: btest-diff pred2.out
# @TEST-EXEC: btest-diff fin.out

@TEST-START-FILE input1.log
#separator \x09
#path	ssh
#fields	b	i	e	c	p	sn	a	d	t	iv	s	sc	ss	se	vc	ve	f
#types	bool	int	enum	count	port	subnet	addr	double	time	interval	string	table	table	table	vector	vector	func
T	-42	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	SSH::foo\x0a{ \x0aif (0 < SSH::i) \x0a\x09return (Foo);\x0aelse\x0a\x09return (Bar);\x0a\x0a}
@TEST-END-FILE
@TEST-START-FILE input2.log
#separator \x09
#path	ssh
#fields	b	i	e	c	p	sn	a	d	t	iv	s	sc	ss	se	vc	ve	f
#types	bool	int	enum	count	port	subnet	addr	double	time	interval	string	table	table	table	vector	vector	func
T	-43	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	SSH::foo\x0a{ \x0aif (0 < SSH::i) \x0a\x09return (Foo);\x0aelse\x0a\x09return (Bar);\x0a\x0a}
@TEST-END-FILE
@TEST-START-FILE input3.log
#separator \x09
#path	ssh
#fields	b	i	e	c	p	sn	a	d	t	iv	s	sc	ss	se	vc	ve	f
#types	bool	int	enum	count	port	subnet	addr	double	time	interval	string	table	table	table	vector	vector	func
F	-44	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	SSH::foo\x0a{ \x0aif (0 < SSH::i) \x0a\x09return (Foo);\x0aelse\x0a\x09return (Bar);\x0a\x0a}
@TEST-END-FILE

@load base/protocols/ssh
redef exit_only_after_terminate = T;

redef InputAscii::empty_field = "EMPTY";

module A;

type Idx: record {
	i: int;
};

type Val: record {
	b: bool;
	e: Log::ID;
	c: count;
	p: port;
	sn: subnet;
	a: addr;
	d: double;
	t: time;
	iv: interval;
	s: string;
	sc: set[count];
	ss: set[string];
	se: set[string];
	vc: vector of int;
	ve: vector of int;
};

global servers: table[int] of Val = table();

global event_out: file;
global pred1_out: file;
global pred2_out: file;
global fin_out: file;

global try: count;

event line(description: Input::TableDescription, tpe: Input::Event, left: Idx, right: Val)
	{
	print event_out, "============EVENT============";
#	print event_out, "Description";
#	print event_out, description;
#	print event_out, "Type";
#	print event_out, tpe;
#	print event_out, "Left";
#	print event_out, left;
#	print event_out, "Right";
#	print event_out, right;
	}

event zeek_init()
	{
	event_out = open ("../event.out");
	pred1_out = open ("../pred1.out");
	pred2_out = open ("../pred2.out");
	fin_out = open ("../fin.out");
	try = 0;
	# first read in the old stuff into the table...
	Input::add_table([$source="../input.log", $mode=Input::REREAD, $name="ssh", $idx=Idx, $val=Val, $destination=servers, $ev=line,
	$pred(typ: Input::Event, left: Idx, right: Val) = { 
	print pred1_out, "============PREDICATE============";
	print pred1_out, typ;
	print pred1_out, left;
	print pred1_out, right;
	return T;
	}
	]);
	Input::add_table([$source="../input2.log", $mode=Input::REREAD, $name="ssh2", $idx=Idx, $val=Val, $destination=servers, $ev=line,
	$pred(typ: Input::Event, left: Idx, right: Val) = { 
	print pred2_out, "============PREDICATE 2============";
	print pred2_out, typ;
	print pred2_out, left;
	print pred2_out, right;
	return T;
	}
	]);
	}


event Input::end_of_data(name: string, source: string)
	{
	print fin_out, "==========SERVERS============";
	#print fin_out, servers;
	
	try = try + 1;
	if ( try == 2 )
		system("touch got2");
	else if ( try == 3 )
		{
		print fin_out, "done";
		print fin_out, servers;
		close(event_out);
		close(pred1_out);
		close(pred2_out);
		close(fin_out);
		Input::remove("input");
		Input::remove("input2");
		terminate();
		}
	}
