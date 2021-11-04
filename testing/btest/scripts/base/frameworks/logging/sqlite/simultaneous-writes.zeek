# Test simultaneous writes to the same database file.
#
# @TEST-REQUIRES: which sqlite3
# @TEST-REQUIRES: has-writer Zeek::SQLiteWriter

# Don't run this test if we build with '--sanitizers=thread' because we
# disable the shared cache in that case due to a SQLite bug.
# @TEST-REQUIRES: grep -q "#define ZEEK_TSAN" zeek-config.h || test $? == 0
# @TEST-GROUP: sqlite
#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: sqlite3 ssh.sqlite 'select * from ssh' > ssh.select
# @TEST-EXEC: sqlite3 ssh.sqlite 'select * from sshtwo' >> ssh.select
# @TEST-EXEC: btest-diff ssh.select
#
# Testing all possible types.

redef LogSQLite::unset_field = "(unset)";

module SSH;

export {
	redef enum Log::ID += { LOG, LOG2 };

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
	Log::create_stream(SSH::LOG2, [$columns=Log]);
	Log::remove_filter(SSH::LOG, "default");
	Log::remove_filter(SSH::LOG2, "default");

	local filter: Log::Filter = [$name="sqlite", $path="ssh", $config=table(["tablename"] = "ssh"), $writer=Log::WRITER_SQLITE];
	Log::add_filter(SSH::LOG, filter);
	local filter2 = copy(filter);
	filter2$name = "sqlite2";
	filter2$config = table(["tablename"] = "sshtwo");
	Log::add_filter(SSH::LOG2, filter2);

	local empty_set: set[string];
	local empty_vector: vector of string;

	local out = [
		$b=T,
		$i=-42,
		$e=SSH::LOG,
		$c=21,
		$p=123/tcp,
		$sn=10.0.0.1/24,
		$a=1.2.3.4,
		$d=3.14,
		$t=double_to_time(1559847346.10295),
		$iv=100secs,
		$s="hurz",
		$sc=set(1,2,3,4),
		$ss=set("AA", "BB", "CC"),
		$se=empty_set,
		$vc=vector(10, 20, 30),
		$ve=empty_vector,
		$f=foo
		];

	Log::write(SSH::LOG, out);
	Log::write(SSH::LOG2, out);
}
