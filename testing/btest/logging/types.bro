#
# @TEST-EXEC: bro %INPUT
# @TEST-EXEC: btest-diff ssh.log
#
# Testing all possible types.

redef LogAscii::empty_field = "EMPTY";

module SSH;

export {
	redef enum Log::ID += { SSH };

	type Log: record {
		b: bool;
		i: int;
		e: Log::ID;
		c: count;
		p: port;
		sn: subnet;
		n: net;
		a: addr;
		d: double;
		t: time;
		iv: interval;
		s: string;
		sc: set[count];
		ss: set[string];
		se: set[string];
	};
}

event bro_init()
{
	Log::create_stream(SSH, [$columns=Log]);

	local empty_set: set[string];

	Log::write(SSH, [
		$b=T,
		$i=-42,
		$e=SSH,
		$c=21,
		$p=123/tcp,
		$sn=10.0.0.1/24,
		$n=10.0.,
		$a=1.2.3.4,
		$d=3.14,
		$t=network_time(),
		$iv=100secs,
		$s="hurz",
		$sc=set(1,2,3,4),
		$ss=set("AA", "BB", "CC"),
		$se=empty_set
		]);
}

