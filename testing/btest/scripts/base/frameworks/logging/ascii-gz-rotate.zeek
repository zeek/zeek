# Test that log rotation works with compressed logs.
#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: gunzip test.*.log.gz
#

module Test;

export {
	redef enum Log::ID += { LOG };

	type Log: record {
		s: string;
	} &log;
}

redef Log::default_rotation_interval = 1hr;
redef LogAscii::gzip_level = 1;

event zeek_init()
{
	Log::create_stream(Test::LOG, [$columns=Log]);

	Log::write(Test::LOG, [$s="testing"]);
}
