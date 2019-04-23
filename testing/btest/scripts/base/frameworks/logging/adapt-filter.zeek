
# @TEST-EXEC: zeek -b %INPUT 
# @TEST-EXEC: btest-diff ssh-new-default.log
# @TEST-EXEC: test '!' -e ssh.log

module SSH;

export {
	# Create a new ID for our log stream
	redef enum Log::ID += { LOG };

	# Define a record with all the columns the log file can have.
	# (I'm using a subset of fields from ssh-ext for demonstration.)
	type Info: record {
		t: time;
		id: conn_id; # Will be rolled out into individual columns.
		status: string &optional;
		country: string &default="unknown";
	} &log;
}

event zeek_init()
{
	Log::create_stream(SSH::LOG, [$columns=Info]);

	local filter = Log::get_filter(SSH::LOG, "default");
	filter$path= "ssh-new-default";
	Log::add_filter(SSH::LOG, filter);

	local cid = [$orig_h=1.2.3.4, $orig_p=1234/tcp, $resp_h=2.3.4.5, $resp_p=80/tcp];
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="success"]);
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="failure", $country="US"]);
}
