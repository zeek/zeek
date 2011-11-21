#
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

@TEST-START-FILE input.log
#separator \x09
#path	ssh
#fields	b	i	e	c	p	sn	a	d	t	iv	s	sc	ss	se	vc	ve	f
#types	bool	int	enum	count	port	subnet	addr	double	time	interval	string	table	table	table	vector	vector	func
T	-42	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	SSH::foo\x0a{ \x0aif (0 < SSH::i) \x0a\x09return (Foo);\x0aelse\x0a\x09return (Bar);\x0a\x0a}
@TEST-END-FILE

redef InputAscii::empty_field = "EMPTY";

module A;

export {
	redef enum Log::ID += { LOG };
}

type idx: record {
	i: int;
};

type val: record {
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

global servers: table[int] of val = table();

event bro_init()
{
	# first read in the old stuff into the table...
	Input::create_stream(A::LOG, [$source="input.log"]);
	Input::add_tablefilter(A::LOG, [$name="ssh", $idx=idx, $val=val, $destination=servers]);
	Input::force_update(A::LOG);
	print servers;
}
