
# @TEST-EXEC: bro %INPUT 
# @TEST-EXEC: btest-diff ssh.success.log
# @TEST-EXEC: btest-diff ssh.failure.log

module SSH;

export {
	# Create a new ID for our log stream
	redef enum Log::ID += { SSH };

	# Define a record with all the columns the log file can have.
	# (I'm using a subset of fields from ssh-ext for demonstration.)
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

event bro_init()
{
	Log::create_stream(SSH, [$columns=Log]);
	Log::remove_default_filter(SSH);
	Log::add_filter(SSH, [$name="f1", $path="ssh.success", $pred=function(rec: Log): bool { return rec$status == "success"; }]);
	Log::add_filter(SSH, [$name="f2", $path="ssh.failure", $pred=fail]);

    local cid = [$orig_h=1.2.3.4, $orig_p=1234/tcp, $resp_h=2.3.4.5, $resp_p=80/tcp];
	local r: Log = [$t=network_time(), $id=cid, $status="success"];
	Log::write(SSH, r);
	Log::write(SSH, [$t=network_time(), $id=cid, $status="failure", $country="US"]);
	
}
