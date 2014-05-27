#
# @TEST-EXEC: bro -b %INPUT
# @TEST-EXEC: btest-diff ssh.log
#
# Testing all possible types.

redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;

module SSH;

export {
	redef enum Log::ID += { LOG };

	type Log: record {
		t: time;
	} &log;
}

event bro_init()
{
	Log::create_stream(SSH::LOG, [$columns=Log]);
	Log::write(SSH::LOG, [
		$t=(strptime("%Y-%m-%dT%H:%M:%SZ", "2008-07-09T16:13:30Z") + 0.00543210 secs)
		]);
	Log::write(SSH::LOG, [
		$t=(strptime("%Y-%m-%dT%H:%M:%SZ", "1986-12-01T01:01:01Z") + 0.90 secs)
		]);

}

