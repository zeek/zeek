
# @TEST-EXEC: zeek -b %INPUT 
# @TEST-EXEC: btest-diff test.success.log
# @TEST-EXEC: btest-diff test.failure.log

module Test;

export {
	# Create a new ID for our log stream
	redef enum Log::ID += { LOG };

	# Define a record with all the columns the log file can have.
	# (I'm using a subset of fields from ssh for demonstration.)
	type Log: record {
		t: time;
		id: conn_id; # Will be rolled out into individual columns.
		status: string &optional;
		country: string &default="unknown";
	} &log;
}

function fail(rec: Log): bool
	{
	return rec$status != "success";
	}

event zeek_init()
{
	Log::create_stream(Test::LOG, [$columns=Log]);
	Log::remove_default_filter(Test::LOG);
	Log::add_filter(Test::LOG, [$name="f1", $path="test.success", $pred=function(rec: Log): bool { return rec$status == "success"; }]);
	Log::add_filter(Test::LOG, [$name="f2", $path="test.failure", $pred=fail]);

    local cid = [$orig_h=1.2.3.4, $orig_p=1234/tcp, $resp_h=2.3.4.5, $resp_p=80/tcp];
	local r: Log = [$t=network_time(), $id=cid, $status="success"];
	Log::write(Test::LOG, r);
	Log::write(Test::LOG, [$t=network_time(), $id=cid, $status="failure", $country="US"]);
	
}
