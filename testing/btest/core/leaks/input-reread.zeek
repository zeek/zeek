# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: cp input1.log input.log
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -m -b %INPUT
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/got2 60 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: cp input2.log input.log
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/got4 10 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: cp input3.log input.log
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/got6 10 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: cp input4.log input.log
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/got8 10 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: cp input5.log input.log
# @TEST-EXEC: btest-bg-wait 120

@TEST-START-FILE input1.log
#separator \x09
#path	ssh
#fields	b	i	e	c	p	sn	a	d	t	iv	s	sc	ss	se	vc	ve	r.a	r.b
#types	bool	int	enum	count	port	subnet	addr	double	time	interval	string	table	table	table	vector	vector	string	string
T	-42	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	fortytwo	-
@TEST-END-FILE
@TEST-START-FILE input2.log
#separator \x09
#path	ssh
#fields	b	i	e	c	p	sn	a	d	t	iv	s	sc	ss	se	vc	ve	r.a	r.b
#types	bool	int	enum	count	port	subnet	addr	double	time	interval	string	table	table	table	vector	vector	string	string
T	-42	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	fortytwo	-
T	-43	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	fortythree	43
@TEST-END-FILE
@TEST-START-FILE input3.log
#separator \x09
#path	ssh
#fields	b	i	e	c	p	sn	a	d	t	iv	s	sc	ss	se	vc	ve	r.a	r.b
#types	bool	int	enum	count	port	subnet	addr	double	time	interval	string	table	table	table	vector	vector	string	string
T	-42	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	fortytwo	-
F	-43	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	fortythree	43
@TEST-END-FILE
@TEST-START-FILE input4.log
#separator \x09
#path	ssh
#fields	b	i	e	c	p	sn	a	d	t	iv	s	sc	ss	se	vc	ve	r.a	r.b	r.d
#types	bool	int	enum	count	port	subnet	addr	double	time	interval	string	table	table	table	vector	vector	string	string	string
T	-42	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	fortytwo	-	-
F	-43	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	fortythree	43	-
F	-44	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	fortyfour	-	-
F	-45	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	fourtyfive	-	-
F	-46	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	fourtysix	-	-
F	-47	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	fourtyseven	-	-
F	-48	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	fourtyeight	48	f
@TEST-END-FILE
@TEST-START-FILE input5.log
#separator \x09
#path	ssh
#fields	b	i	e	c	p	sn	a	d	t	iv	s	sc	ss	se	vc	ve	r.a	r.b	r.d
#types	bool	int	enum	count	port	subnet	addr	double	time	interval	string	table	table	table	vector	vector	string	string	string
F	-48	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	fourtyeight	48	f
@TEST-END-FILE

@load base/protocols/ssh

redef exit_only_after_terminate = T;
redef InputAscii::empty_field = "EMPTY";

module A;

type Sub: record {
	a: string;
	b: string &optional;
	c: string &optional;
	d: string &optional;
};

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
	r: Sub;
};

global servers: table[int] of Val = table();

global outfile: file;

global try: count;

event servers_ev(description: Input::EventDescription, tpe: Input::Event, item: Val)
	{
	print outfile, "============EVENT EVENT============";
	print outfile, item;
	}

event line(description: Input::TableDescription, tpe: Input::Event, left: Idx, right: Val)
	{
	print outfile, "============TABLE EVENT============";
	print outfile, "Left";
	print outfile, left;
	print outfile, "Right";
	print outfile, right;
	}

event zeek_init()
	{
	outfile = open("../out");
	try = 0;
	# first read in the old stuff into the table...
	Input::add_table([$source="../input.log", $mode=Input::REREAD, $name="ssh", $idx=Idx, $val=Val, $destination=servers, $ev=line,
	$pred(typ: Input::Event, left: Idx, right: Val) = { 
	print outfile, "============PREDICATE============";
	print outfile, left;
	print outfile, right;
	return T;
	}
	]);
	Input::add_event([$source="../input.log", $mode=Input::REREAD, $name="sshevent", $fields=Val, $ev=servers_ev]);
	}


event Input::end_of_data(name: string, source: string)
	{
	if ( name == "ssh" ) {
		print outfile, "==========SERVERS============";
		print outfile, servers;
	} else {
		print outfile, "==========END OF EVENTS EVENTS===========";
	}
	
	try = try + 1;

	if ( try == 2 )
		system("touch got2");
	else if ( try == 4 )
		system("touch got4");
	else if ( try == 6 )
		system("touch got6");
	else if ( try == 8 )
		system("touch got8");
	else if ( try == 10 )
		{
		print outfile, "done";
		close(outfile);
		Input::remove("input");
		terminate();
		}
	}
