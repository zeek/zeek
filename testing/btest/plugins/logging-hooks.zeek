# @TEST-EXEC: ${DIST}/aux/bro-aux/plugin-support/init-plugin -u . Log Hooks
# @TEST-EXEC: cp -r %DIR/logging-hooks-plugin/* .
# @TEST-EXEC: ./configure --bro-dist=${DIST} && make
# @TEST-EXEC: BRO_PLUGIN_ACTIVATE="Log::Hooks" BRO_PLUGIN_PATH=`pwd` zeek -b %INPUT 2>&1 | $SCRIPTS/diff-remove-abspath | sort | uniq  >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff ssh.log

redef LogAscii::empty_field = "EMPTY";

module SSH;

export {
	redef enum Log::ID += { LOG };

	type Log: record {
		b: bool;
		i: int &optional;
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

	local i = 0;
	while ( ++i < 4 )
		Log::write(SSH::LOG, [
			$b=T,
			$i=-i,
			$e=SSH::LOG,
			$c=21,
			$p=123/tcp,
			$sn=10.0.0.1/24,
			$a=1.2.3.4,
			$d=3.14,
			$t=network_time(),
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
