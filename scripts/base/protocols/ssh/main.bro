##! Base SSH analysis script.  The heuristic to blindly determine success or 
##! failure for SSH connections is implemented here.  At this time, it only
##! uses the size of the data being returned from the server to make the
##! heuristic determination about success of the connection.  
##! Requires that :bro:id:`use_conn_size_analyzer` is set to T!  The heuristic
##! is not attempted if the connection size analyzer isn't enabled.

@load base/frameworks/notice
@load base/utils/site
@load base/utils/thresholds
@load base/utils/conn-ids
@load base/utils/directions-and-hosts

module SSH;

export {
	## The SSH protocol logging stream identifier.
	redef enum Log::ID += { LOG };
	
	redef enum Notice::Type += { 
		## Indicates that a heuristically detected "successful" SSH 
		## authentication occurred.
		Login 
	};

	type Info: record {
		## Time when the SSH connection began.
		ts:              time         &log;
		## Unique ID for the connection.
		uid:             string       &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:              conn_id      &log;
		## Indicates if the login was heuristically guessed to be "success"
		## or "failure".
		status:          string       &log &optional;
		## Direction of the connection.  If the client was a local host 
		## logging into an external host, this would be OUTBOUND. INBOUND
		## would be set for the opposite situation.
		# TODO: handle local-local and remote-remote better.
		direction:       Direction    &log &optional;
		## Software string from the client.
		client:          string       &log &optional;
		## Software string from the server.
		server:          string       &log &optional;
		## Amount of data returned from the server. This is currently
		## the only measure of the success heuristic and it is logged to 
		## assist analysts looking at the logs to make their own determination
		## about the success on a case-by-case basis.
		resp_size:       count        &log &default=0;
		
		## Indicate if the SSH session is done being watched.
		done:            bool         &default=F;
	};
	
	## The size in bytes of data sent by the server at which the SSH 
	## connection is presumed to be successful.
	const authentication_data_size = 5500 &redef;
	
	## If true, we tell the event engine to not look at further data
	## packets after the initial SSH handshake. Helps with performance
	## (especially with large file transfers) but precludes some
	## kinds of analyses (e.g., tracking connection size).
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

# Configure DPD and the packet filter
redef capture_filters += { ["ssh"] = "tcp port 22" };
redef dpd_config += { [ANALYZER_SSH] = [$ports = set(22/tcp)] };

redef likely_server_ports += { 22/tcp };

redef record connection += {
	ssh: Info &optional;
};

event bro_init() &priority=5
{
	Log::create_stream(SSH::LOG, [$columns=Info, $ev=log_ssh]);
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
	# If done watching this connection, just return.
	if ( c$ssh$done )
		return;
	
	# Make sure conn_size_analyzer is active by checking 
	# resp$num_bytes_ip.  In general it should always be active though.
	if ( ! c$resp?$num_bytes_ip )
		return;
	
	# Remove the IP and TCP header length from the total size.
	# TODO: Fix for IPv6.  This whole approach also seems to break in some 
	#       cases where there are more header bytes than num_bytes_ip.
	local header_bytes = c$resp$num_pkts*32 + c$resp$num_pkts*20;
	local server_bytes = c$resp$num_bytes_ip;
	if ( server_bytes >= header_bytes )
		server_bytes = server_bytes - header_bytes;
	else
		server_bytes = c$resp$size;
	
	# If this is still a live connection and the byte count has not crossed 
	# the threshold, just return and let the rescheduled check happen later.
	if ( ! done && server_bytes < authentication_data_size )
		return;

	# Make sure the server has sent back more than 50 bytes to filter out
	# hosts that are just port scanning.  Nothing is ever logged if the server
	# doesn't send back at least 50 bytes.
	if ( server_bytes < 50 )
		return;

	c$ssh$direction = Site::is_local_addr(c$id$orig_h) ? OUTBOUND : INBOUND;
	c$ssh$resp_size = server_bytes;
	
	if ( server_bytes < authentication_data_size )
		{
		c$ssh$status  = "failure";
		event SSH::heuristic_failed_login(c);
		}
	else
		{ 
		# presumed successful login
		c$ssh$status = "success";
		event SSH::heuristic_successful_login(c);
		}
	
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

event SSH::heuristic_successful_login(c: connection) &priority=-5
	{
	NOTICE([$note=Login, 
	        $msg="Heuristically detected successful SSH login.",
	        $conn=c]);
	
	Log::write(SSH::LOG, c$ssh);
	}
event SSH::heuristic_failed_login(c: connection) &priority=-5
	{
	Log::write(SSH::LOG, c$ssh);
	}

event connection_state_remove(c: connection) &priority=-5
	{
	if ( c?$ssh )
		check_ssh_connection(c, T);
	}

event ssh_watcher(c: connection)
	{
	local id = c$id;
	# don't go any further if this connection is gone already!
	if ( ! connection_exists(id) )
		return;

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
