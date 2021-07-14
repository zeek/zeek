# This test verifies update events, predicates, and multiple data
# updates when using Input::REREAD mode.

# @TEST-EXEC: mv input1.log input.log
# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/got1 15 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: mv input2.log input.log
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/got2 15 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: mv input3.log input.log
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/got3 15 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: mv input4.log input.log
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/got4 15 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: mv input5.log input.log
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff servers.out
# @TEST-EXEC: btest-diff events.out
# @TEST-EXEC: btest-diff preds.out

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
T	-42	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	SSH::foo\x0a{ \x0aif (0 < SSH::i) \x0a\x09return (Foo);\x0aelse\x0a\x09return (Bar);\x0a\x0a}
T	-43	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	SSH::foo\x0a{ \x0aif (0 < SSH::i) \x0a\x09return (Foo);\x0aelse\x0a\x09return (Bar);\x0a\x0a}
@TEST-END-FILE
@TEST-START-FILE input3.log
#separator \x09
#path	ssh
#fields	b	i	e	c	p	sn	a	d	t	iv	s	sc	ss	se	vc	ve	f
#types	bool	int	enum	count	port	subnet	addr	double	time	interval	string	table	table	table	vector	vector	func
T	-42	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	SSH::foo\x0a{ \x0aif (0 < SSH::i) \x0a\x09return (Foo);\x0aelse\x0a\x09return (Bar);\x0a\x0a}
F	-43	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	SSH::foo\x0a{ \x0aif (0 < SSH::i) \x0a\x09return (Foo);\x0aelse\x0a\x09return (Bar);\x0a\x0a}
@TEST-END-FILE
@TEST-START-FILE input4.log
#separator \x09
#path	ssh
#fields	b	i	e	c	p	sn	a	d	t	iv	s	sc	ss	se	vc	ve	f
#types	bool	int	enum	count	port	subnet	addr	double	time	interval	string	table	table	table	vector	vector	func
T	-42	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	SSH::foo\x0a{ \x0aif (0 < SSH::i) \x0a\x09return (Foo);\x0aelse\x0a\x09return (Bar);\x0a\x0a}
F	-43	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	SSH::foo\x0a{ \x0aif (0 < SSH::i) \x0a\x09return (Foo);\x0aelse\x0a\x09return (Bar);\x0a\x0a}
F	-44	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	SSH::foo\x0a{ \x0aif (0 < SSH::i) \x0a\x09return (Foo);\x0aelse\x0a\x09return (Bar);\x0a\x0a}
F	-45	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	SSH::foo\x0a{ \x0aif (0 < SSH::i) \x0a\x09return (Foo);\x0aelse\x0a\x09return (Bar);\x0a\x0a}
0	-46	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	SSH::foo\x0a{ \x0aif (0 < SSH::i) \x0a\x09return (Foo);\x0aelse\x0a\x09return (Bar);\x0a\x0a}
F	-47	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	SSH::foo\x0a{ \x0aif (0 < SSH::i) \x0a\x09return (Foo);\x0aelse\x0a\x09return (Bar);\x0a\x0a}
F	-48	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	SSH::foo\x0a{ \x0aif (0 < SSH::i) \x0a\x09return (Foo);\x0aelse\x0a\x09return (Bar);\x0a\x0a}
@TEST-END-FILE
@TEST-START-FILE input5.log
#separator \x09
#path	ssh
#fields	b	i	e	c	p	sn	a	d	t	iv	s	sc	ss	se	vc	ve	f
#types	bool	int	enum	count	port	subnet	addr	double	time	interval	string	table	table	table	vector	vector	func
F	-48	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	SSH::foo\x0a{ \x0aif (0 < SSH::i) \x0a\x09return (Foo);\x0aelse\x0a\x09return (Bar);\x0a\x0a}
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

type servers_type: table[int] of Val;
global servers: servers_type = table();

global events_file = open("../events.out");
global predicates_file = open("../preds.out");
global servers_file = open("../servers.out");

global try: count;

event line(description: Input::TableDescription, tpe: Input::Event, left: Idx, right: Val)
	{
	# Printing description details here avoids printing the
	# destination table itself. Its content is not deterministic
	# at the time this event handler runs: it depends on how many
	# entries the reader backend thread has sent over.
	print events_file, "============EVENT============";
	print events_file, "Description";
	print events_file, "  source", description$source;
	print events_file, "  reader", description$reader;
	print events_file, "  mode", description$mode;
	print events_file, "  name", description$name;
	print events_file, fmt("  destination[left = %s]", left$i),
	    (description$destination as servers_type)[left$i];
	print events_file, "  idx", description$idx;
	print events_file, "  val", description$val;
	print events_file, "  want_record", description$want_record;
	print events_file, "Type", tpe;
	print events_file, "Left", left;
	print events_file, "Right", right;
	}

event zeek_init()
	{
	try = 0;
	# first read in the old stuff into the table...
	Input::add_table([$source="../input.log", $mode=Input::REREAD, $name="ssh",
	                  $idx=Idx, $val=Val, $destination=servers, $ev=line,
	                  $pred(typ: Input::Event, left: Idx, right: Val) = {
	                      print predicates_file, "============PREDICATE============";
	                      print predicates_file, typ;
	                      print predicates_file, left;
	                      print predicates_file, right;
	                      return T;
	                      }
	]);
	}


event Input::end_of_data(name: string, source: string)
	{
	print servers_file, "==========SERVERS============";
	print servers_file, servers;

	try = try + 1;

	if ( try == 1 )
		system("touch got1");
	else if ( try == 2 )
		system("touch got2");
	else if ( try == 3 )
		system("touch got3");
	else if ( try == 4 )
		system("touch got4");
	else if ( try == 5 )
		{
		print servers_file, "done";
		close(events_file);
		close(predicates_file);
		close(servers_file);
		Input::remove("input");
		terminate();
		}
	}
