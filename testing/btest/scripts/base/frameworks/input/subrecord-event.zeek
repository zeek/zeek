# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff out

@TEST-START-FILE input.log
#separator \x09
#path	ssh
#fields	sub.b	i	sub.e	sub.c	sub.p	sub.sn	sub.two.a	sub.two.d	t	iv	s	sc	ss	se	vc	ve	f
#types	bool	int	enum	count	port	subnet	addr	double	time	interval	string	table	table	table	vector	vector	func
T	-42	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	SSH::foo\x0a{ \x0aif (0 < SSH::i) \x0a\x09return (Foo);\x0aelse\x0a\x09return (Bar);\x0a\x0a}
@TEST-END-FILE

@load base/protocols/ssh
redef exit_only_after_terminate = T;

global outfile: file;
global try: count;

redef InputAscii::empty_field = "EMPTY";

module A;

type Idx: record {
	i: int;
};

type SubVal2: record {
	a: addr;
	d: double;
};

type SubVal: record {
	b: bool;
	e: Log::ID;
	c: count;
	p: port;
	sn: subnet;
	two: SubVal2;
};

type Val: record {
	sub: SubVal;
	t: time;
	iv: interval;
	s: string;
	sc: set[count];
	ss: set[string];
	se: set[string];
	vc: vector of int;
	ve: vector of int;
};



event line(description: Input::EventDescription, tpe: Input::Event, value: Val)
	{
	print outfile, value;
	try = try + 1;
	if ( try == 1 )
		{
		Input::remove("ssh");
		close(outfile);
		terminate();
		}
	}

event zeek_init()
	{
	try = 0;	
	outfile = open("../out");
	Input::add_event([$source="../input.log", $name="ssh", $fields=Val, $ev=line, $want_record=T]);
	}
