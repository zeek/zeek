#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff ssh.log
#
# Testing all possible types.

redef LogAscii::use_json = T;

module SSH;

export {
	redef enum Log::ID += { LOG };

	type Log: record {
		b: bool;
		i: int;
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
		vc: vector of count;
		ve: vector of string;
		f: function(i: count) : string;
	} &log;
}

function foo(i : count) : string
	{
	if ( i > 0 )
		return "Foo";
	else
		return "Bar";
	}

event zeek_init()
{
	Log::create_stream(SSH::LOG, [$columns=Log]);

	local empty_set: set[string];
	local empty_vector: vector of string;

	Log::write(SSH::LOG, [
		$b=T,
		$i=-42,
		$e=SSH::LOG,
		$c=21,
		$p=123/tcp,
		$sn=10.0.0.1/24,
		$a=1.2.3.4,
		$d=3.14,
		$t=(strptime("%Y-%m-%dT%H:%M:%SZ", "2008-07-09T16:13:30Z") + 0.543210 secs),
		$iv=100secs,
		$s="hurz",
		$sc=set(1,2,3,4),
		$ss=set("AA", "BB", "CC"),
		$se=empty_set,
		$vc=vector(10, 20, 30),
		$ve=empty_vector,
		$f=foo
		]);
}

