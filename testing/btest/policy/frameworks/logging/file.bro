#
# @TEST-EXEC: BRO_NO_BASE_SCRIPTS=1 bro %INPUT
# @TEST-EXEC: btest-diff ssh.log

module SSH;

export {
	redef enum Log::ID += { SSH };

	type Log: record {
		t: time;
		f: file;
	} &log;
}

const foo_log = open_log_file("Foo") &redef;

event bro_init()
{
	Log::create_stream(SSH, [$columns=Log]);
	Log::write(SSH, [$t=network_time(), $f=foo_log]);
}

