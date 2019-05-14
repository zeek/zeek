
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: ( ls static-*; cat static-* ) >output
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

global c = -1;

function path_func(id: Log::ID, path: string, rec: Log) : string
	{
	c = (c + 1) % 3;

	return fmt("%s-%d-%s", path, c, rec$country);
	}

event zeek_init()
{
	Log::create_stream(SSH::LOG, [$columns=Log]);
	Log::remove_default_filter(SSH::LOG);

	Log::add_filter(SSH::LOG, [$name="dyn", $path="static-prefix", $path_func=path_func]);

	Log::set_buf(SSH::LOG, F);

    local cid = [$orig_h=1.2.3.4, $orig_p=1234/tcp, $resp_h=2.3.4.5, $resp_p=80/tcp];
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="success"]);
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="failure", $country="US"]);
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="failure", $country="UK"]);
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="success", $country="BR"]);
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="failure", $country="MX"]);
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="failure", $country="MX2"]);
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="failure", $country="MX3"]);
}
