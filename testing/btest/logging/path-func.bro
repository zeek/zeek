
# @TEST-EXEC: bro %INPUT
# @TEST-EXEC: ( ls static-*; cat static-* ) >output
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

global c = -1;

function path_func(id: Log_ID, path: string) : string
	{
	c = (c + 1) % 3;

	return fmt("%s-%d", path, c);
	}

event bro_init()
{
	log_create_stream(LOG_SSH, SSH::Log, ssh_log);

	log_add_filter(LOG_SSH, [$name="dyn", $path="static-prefix", $path_func=path_func]);

	log_set_buf(LOG_SSH, F);

    local cid = [$orig_h=1.2.3.4, $orig_p=1234/tcp, $resp_h=2.3.4.5, $resp_p=80/tcp];
	log_write(LOG_SSH, [$t=network_time(), $id=cid, $status="success"]);
	log_write(LOG_SSH, [$t=network_time(), $id=cid, $status="failure", $country="US"]);
	log_write(LOG_SSH, [$t=network_time(), $id=cid, $status="failure", $country="UK"]);
	log_write(LOG_SSH, [$t=network_time(), $id=cid, $status="success", $country="BR"]);
	log_write(LOG_SSH, [$t=network_time(), $id=cid, $status="failure", $country="MX"]);
	log_write(LOG_SSH, [$t=network_time(), $id=cid, $status="failure", $country="MX2"]);
	log_write(LOG_SSH, [$t=network_time(), $id=cid, $status="failure", $country="MX3"]);
}
