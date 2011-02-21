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
	# Create the stream.
	# First argument is the ID for the stream.
	# Second argument is the log record type.
	# Third argument is the log event, which must receive a single argument of type arg2.
	log_create_stream(LOG_SSH, SSH::Log, ssh_log);

	# Add a default filter that simply logs everything to "ssh.log" using the default writer.
	Log_add_default_filter(LOG_SSH);

	# Printing headers for the filters doesn't work yet either and needs to 
	# be considered in the final design. (based on the "select" set).
	#Log::add_filter("ssh", [$name="successful logins",
	#                            #$pred(rec: Log) = { print rec$status; return T; },
	#                            $path="ssh-logins",
	#                            #$select=set("t"),
	#                            $writer=Log::WRITER_CSV]);

    local cid = [$orig_h=1.2.3.4, $orig_p=1234/tcp, $resp_h=2.3.4.5, $resp_p=80/tcp];

	local r: Log = [$t=network_time(), $id=cid, $status="success"];

	# Log something.
	log_write(LOG_SSH, r);
	log_write(LOG_SSH, [$t=network_time(), $id=cid, $status="failure", $country="US"]);
	log_write(LOG_SSH, [$t=network_time(), $id=cid, $status="failure", $country="UK"]);
	log_write(LOG_SSH, [$t=network_time(), $id=cid, $status="success", $country="BR"]);
	log_write(LOG_SSH, [$t=network_time(), $id=cid, $status="failure", $country="MX"]);
	
}

event ssh_log(rec: Log)
	{
	print fmt("Ran the log handler from the same module.  Extracting time: %0.6f", rec$t);
	print rec;
	}
#
#
#module WHATEVER;
#
#event SSH::log(rec: SSH::Log)
#	{
#	print fmt("Ran the SSH::log handler from a different module.  Extracting time: %0.6f", rec$t);
#	}
