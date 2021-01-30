#
# @TEST-EXEC: zeek -b -B logging %INPUT
# @TEST-EXEC: btest-diff ssh.log
# @TEST-EXEC: btest-diff ssh.failure.log
# @TEST-EXEC: btest-diff .stdout

module SSH;

export {
	# Create a new ID for our log stream
	redef enum Log::ID += { LOG };

	# Define a record with all the columns the log file can have.
	# (I'm using a subset of fields from ssh-ext for demonstration.)
	type Log: record {
		t: time;
		id: conn_id; # Will be rolled out into individual columns.
		status: string;
		country: string &default="unknown";
	} &log;
}

hook fail_only(rec: Log, id: Log::ID, filter: Log::Filter)
	{
	if ( rec$status != "failure" )
		break;
	}

event zeek_init()
{
	Log::create_stream(SSH::LOG, [$columns=Log]);
	Log::add_filter(SSH::LOG, [$name="f1", $path="ssh.failure", $policy=fail_only]);

	local cid = [$orig_h=1.2.3.4, $orig_p=1234/tcp, $resp_h=2.3.4.5, $resp_p=80/tcp];

	# Log something.
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="failure", $country="US"]);
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="failure", $country="UK"]);
	print Log::get_filter_names(SSH::LOG);

	Log::remove_filter(SSH::LOG, "f1");
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="failure", $country="BR"]);

	Log::remove_filter(SSH::LOG, "default");
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="failure", $country="MX"]);

	Log::remove_filter(SSH::LOG, "doesn-not-exist");
	print Log::get_filter_names(SSH::LOG);
}

