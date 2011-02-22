
# @TEST-EXEC: bro %INPUT 
# @TEST-EXEC: btest-diff ssh.success.log
# @TEST-EXEC: btest-diff ssh.failure.log

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

function fail(rec: Log): bool
	{
	return rec$status != "success";
	}

event bro_init()
{
	log_create_stream(LOG_SSH, SSH::Log, ssh_log);

	log_add_filter(LOG_SSH, [$name="f1", $path="ssh.success", $pred=function(rec: Log): bool { return rec$status == "success"; }]);
	log_add_filter(LOG_SSH, [$name="f2", $path="ssh.failure", $pred=fail]);

    local cid = [$orig_h=1.2.3.4, $orig_p=1234/tcp, $resp_h=2.3.4.5, $resp_p=80/tcp];
	local r: Log = [$t=network_time(), $id=cid, $status="success"];
	log_write(LOG_SSH, r);
	log_write(LOG_SSH, [$t=network_time(), $id=cid, $status="failure", $country="US"]);
	
}
