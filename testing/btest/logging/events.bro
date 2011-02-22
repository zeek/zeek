
# @TEST-EXEC: bro %INPUT >output
# @TEST-EXEC: btest-diff output

module SSH;

@load logging

export {
	# Create a new ID for our log stream
	redef enum Log_ID += { LOG_SSH };

	# Define a record with all the columns the log file can have.
	# (I'm using a subset of fields from ssh-ext for demonstration.)
	type Log: record {
		t: time;
		id: conn_id; # Will be rolled out into individual columns.
		status: string &optional;
		country: string &default="unknown";
	};
}

global ssh_log: event(rec: Log);

event bro_init()
{
	log_create_stream(LOG_SSH, SSH::Log, ssh_log);
	Log_add_default_filter(LOG_SSH);

    local cid = [$orig_h=1.2.3.4, $orig_p=1234/tcp, $resp_h=2.3.4.5, $resp_p=80/tcp];
	local r: Log = [$t=network_time(), $id=cid, $status="success"];
	log_write(LOG_SSH, r);
	log_write(LOG_SSH, [$t=network_time(), $id=cid, $status="failure", $country="US"]);
	
}

event ssh_log(rec: Log)
	{
	print rec;
	}
