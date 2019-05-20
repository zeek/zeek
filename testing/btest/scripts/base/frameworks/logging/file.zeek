#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff ssh.log

module SSH;

export {
	redef enum Log::ID += { LOG };

	type Log: record {
		t: time;
		f: file;
	} &log;
}

const foo_log = open_log_file("Foo") &redef;

event zeek_init()
{
	Log::create_stream(SSH::LOG, [$columns=Log]);
	Log::write(SSH::LOG, [$t=network_time(), $f=foo_log]);
}

