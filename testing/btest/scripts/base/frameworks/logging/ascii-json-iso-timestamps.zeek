#
# @TEST-EXEC: zeek -b %INPUT
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

event zeek_init()
{
	Log::create_stream(SSH::LOG, [$columns=Log]);
	Log::write(SSH::LOG, [
		$t=(strptime("%Y-%m-%dT%H:%M:%SZ", "2008-07-09T16:13:30Z") + 0.00543210 secs)
		]);
	Log::write(SSH::LOG, [
		$t=(strptime("%Y-%m-%dT%H:%M:%SZ", "1986-12-01T01:01:01Z") + 0.90 secs)
		]);

	Log::write(SSH::LOG, [
		$t=(strptime("%Y-%m-%dT%H:%M:%SZ", "1970-01-01T00:00:00Z") - 0.4 secs)
		]);
	Log::write(SSH::LOG, [
		$t=(strptime("%Y-%m-%dT%H:%M:%SZ", "1970-01-01T00:00:00Z") - 0.5 secs)
		]);
	Log::write(SSH::LOG, [
		$t=(strptime("%Y-%m-%dT%H:%M:%SZ", "1970-01-01T00:00:00Z") - 0.6 secs)
		]);
	Log::write(SSH::LOG, [
		$t=(strptime("%Y-%m-%dT%H:%M:%SZ", "1970-01-01T00:00:00Z") - 1.0 secs)
		]);
	Log::write(SSH::LOG, [
		$t=(strptime("%Y-%m-%dT%H:%M:%SZ", "1970-01-01T00:00:00Z") - 1.4 secs)
		]);
	Log::write(SSH::LOG, [
		$t=(strptime("%Y-%m-%dT%H:%M:%SZ", "1970-01-01T00:00:00Z") - 1.5 secs)
		]);
	Log::write(SSH::LOG, [
		$t=(strptime("%Y-%m-%dT%H:%M:%SZ", "1970-01-01T00:00:00Z") - 1.6 secs)
		]);
	Log::write(SSH::LOG, [
		$t=(strptime("%Y-%m-%dT%H:%M:%SZ", "1970-01-01T00:00:00Z") - 99 secs)
		]);

}

