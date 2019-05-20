
# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

module SSH;

export {
	# Create a new ID for our log stream
	redef enum Log::ID += { LOG };

	# Define a record with all the columns the log file can have.
	# (I'm using a subset of fields from ssh-ext for demonstration.)
	type Log: record {
		t: time;
		id: conn_id; # Will be rolled out into individual columns.
		status: string &optional;
		country: string &default="unknown";
	} &log;
}

global ssh_log: event(rec: Log);

event zeek_init()
{
	Log::create_stream(SSH::LOG, [$columns=Log, $ev=ssh_log]);

    local cid = [$orig_h=1.2.3.4, $orig_p=1234/tcp, $resp_h=2.3.4.5, $resp_p=80/tcp];
	local r: Log = [$t=network_time(), $id=cid, $status="success"];
	Log::write(SSH::LOG, r);
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="failure", $country="US"]);
	
}

event ssh_log(rec: Log)
	{
	print rec;
	}
