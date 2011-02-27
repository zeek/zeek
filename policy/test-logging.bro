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
	};
}

global log_ssh: event(rec: Log);

function fail(rec: Log): bool
	{
	return rec$status != "success";
	}

event bro_init()
{
	# Create the stream.
	# First argument is the ID for the stream.
	# Second argument is a record of type Log::Stream.
	Log::create_stream(SSH, [$columns=Log, $ev=log_ssh]);

	Log::add_filter(SSH, [$name="f1", $path="ssh.success", $pred=function(rec: Log): bool { return rec$status == "success"; }]);
	Log::add_filter(SSH, [$name="f2", $path="ssh.failure", $pred=fail]);

    local cid = [$orig_h=1.2.3.4, $orig_p=1234/tcp, $resp_h=2.3.4.5, $resp_p=80/tcp];

	local r: Log = [$t=network_time(), $id=cid, $status="success"];

	# Log something.
	Log::write(SSH, r);
	Log::write(SSH, [$t=network_time(), $id=cid, $status="failure", $country="US"]);
	Log::write(SSH, [$t=network_time(), $id=cid, $status="failure", $country="UK"]);
	Log::write(SSH, [$t=network_time(), $id=cid, $status="success", $country="BR"]);
	Log::write(SSH, [$t=network_time(), $id=cid, $status="failure", $country="MX"]);
}

event log_ssh(rec: Log)
	{
	print fmt("Ran the log handler from the same module.  Extracting time: %0.6f", rec$t);
	print rec;
	}
