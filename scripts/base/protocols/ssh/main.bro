##! Base SSH analysis script.  The heuristic to blindly determine success or
##! failure for SSH connections is implemented here.  At this time, it only
##! uses the size of the data being returned from the server to make the
##! heuristic determination about success of the connection.
##! Requires that :bro:id:`use_conn_size_analyzer` is set to T!  The heuristic
##! is not attempted if the connection size analyzer isn't enabled.

@load base/protocols/conn
@load base/frameworks/notice
@load base/utils/site
@load base/utils/thresholds
@load base/utils/conn-ids
@load base/utils/directions-and-hosts

module SSH;

export {
	## The SSH protocol logging stream identifier.
	redef enum Log::ID += { LOG };

	type Info: record {
		## Time when the SSH connection began.
		ts:              time         &log;
		## Unique ID for the connection.
		uid:             string       &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:              conn_id      &log;
		## Indicates if the login was heuristically guessed to be
		## "success", "failure", or "undetermined".
		status:          string       &log &default="undetermined";
		## Direction of the connection.  If the client was a local host
		## logging into an external host, this would be OUTBOUND. INBOUND
		## would be set for the opposite situation.
		# TODO: handle local-local and remote-remote better.
		direction:       Direction    &log &optional;
		## Software string from the client.
		client:          string       &log &optional;
		## Software string from the server.
		server:          string       &log &optional;
		## Indicate if the SSH session is done being watched.
		done:            bool         &default=F;
	};

	## The size in bytes of data sent by the server at which the SSH
	## connection is presumed to be successful.
	const authentication_data_size = 4000 &redef;

	## If true, we tell the event engine to not look at further data
	## packets after the initial SSH handshake. Helps with performance
	## (especially with large file transfers) but precludes some
	## kinds of analyses.
	const skip_processing_after_detection = F &redef;

	## Event that is generated when the heuristic thinks that a login
	## was successful.
	global heuristic_successful_login: event(c: connection);

	## Event that is generated when the heuristic thinks that a login
	## failed.
	global heuristic_failed_login: event(c: connection);

	## Event that can be handled to access the :bro:type:`SSH::Info`
	## record as it is sent on to the logging framework.
	global log_ssh: event(rec: Info);
}

redef record connection += {
	ssh: Info &optional;
};

const ports = { 22/tcp };
redef likely_server_ports += { ports };

event bro_init() &priority=5
{
	Log::create_stream(SSH::LOG, [$columns=Info, $ev=log_ssh]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_SSH, ports);
}

function set_session(c: connection)
	{
	if ( ! c?$ssh )
		{
		local info: Info;
		info$ts=network_time();
		info$uid=c$uid;
		info$id=c$id;
		c$ssh = info;
		}
	}

function check_ssh_connection(c: connection, done: bool)
	{
	# If already done watching this connection, just return.
	if ( c$ssh$done )
		return;

	if ( done )
		{
		# If this connection is done, then we can look to see if
		# this matches the conditions for a failed login.  Failed
		# logins are only detected at connection state removal.

		if ( # Require originators and responders to have sent at least 50 bytes.
		     c$orig$size > 50 && c$resp$size > 50 &&
		     # Responders must be below 4000 bytes.
		     c$resp$size < authentication_data_size &&
		     # Responder must have sent fewer than 40 packets.
		     c$resp$num_pkts < 40 &&
		     # If there was a content gap we can't reliably do this heuristic.
		     c?$conn && c$conn$missed_bytes == 0 )# &&
		     # Only "normal" connections can count.
		     #c$conn?$conn_state && c$conn$conn_state in valid_states )
			{
			c$ssh$status = "failure";
			event SSH::heuristic_failed_login(c);
			}

		if ( c$resp$size >= authentication_data_size )
			{
			c$ssh$status = "success";
			event SSH::heuristic_successful_login(c);
			}
		}
	else
		{
		# If this connection is still being tracked, then it's possible
		# to watch for it to be a successful connection.
		if ( c$resp$size >= authentication_data_size )
			{
			c$ssh$status = "success";
			event SSH::heuristic_successful_login(c);
			}
		else
			# This connection must be tracked longer.  Let the scheduled
			# check happen again.
			return;
		}

	# Set the direction for the log.
	c$ssh$direction = Site::is_local_addr(c$id$orig_h) ? OUTBOUND : INBOUND;

	# Set the "done" flag to prevent the watching event from rescheduling
	# after detection is done.
	c$ssh$done=T;

	if ( skip_processing_after_detection )
		{
		# Stop watching this connection, we don't care about it anymore.
		skip_further_processing(c$id);
		set_record_packets(c$id, F);
		}
	}


event heuristic_successful_login(c: connection) &priority=-5
	{
	Log::write(SSH::LOG, c$ssh);
	}

event heuristic_failed_login(c: connection) &priority=-5
	{
	Log::write(SSH::LOG, c$ssh);
	}

event connection_state_remove(c: connection) &priority=-5
	{
	if ( c?$ssh )
		{
		check_ssh_connection(c, T);
		if ( c$ssh$status == "undetermined" )
			Log::write(SSH::LOG, c$ssh);
		}
	}

event ssh_watcher(c: connection)
	{
	local id = c$id;
	# don't go any further if this connection is gone already!
	if ( ! connection_exists(id) )
		return;

	lookup_connection(c$id);
	check_ssh_connection(c, F);
	if ( ! c$ssh$done )
		schedule +15secs { ssh_watcher(c) };
	}

event ssh_server_version(c: connection, version: string) &priority=5
	{
	set_session(c);
	c$ssh$server = version;
	}

event ssh_client_version(c: connection, version: string) &priority=5
	{
	set_session(c);
	c$ssh$client = version;

	# The heuristic detection for SSH relies on the ConnSize analyzer.
	# Don't do the heuristics if it's disabled.
	if ( use_conn_size_analyzer )
		schedule +15secs { ssh_watcher(c) };
	}
