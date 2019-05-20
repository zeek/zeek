#
# Check if set works in last position (the describe call in sqlite.cc has a good
# chance of being off by one if someone changes it).
#
# @TEST-REQUIRES: which sqlite3
# @TEST-REQUIRES: has-writer Bro::SQLiteWriter
# @TEST-GROUP: sqlite
#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: sqlite3 ssh.sqlite 'select * from ssh' > ssh.select
# @TEST-EXEC: btest-diff ssh.select
#
# Testing all possible types.

redef LogSQLite::unset_field = "(unset)";

module SSH;

export {
	redef enum Log::ID += { LOG };

	type Log: record {
		ss: set[string];
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
	Log::remove_filter(SSH::LOG, "default");

	local filter: Log::Filter = [$name="sqlite", $path="ssh", $writer=Log::WRITER_SQLITE];
	Log::add_filter(SSH::LOG, filter);

	local empty_set: set[string];
	local empty_vector: vector of string;

	Log::write(SSH::LOG, [
		$ss=set("AA", "BB", "CC")
		]);
}

