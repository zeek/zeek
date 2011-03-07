@load functions
@load notice

module SSH;

redef enum Notice::Type += {
	SSH_Login,
	SSH_PasswordGuessing,
	SSH_LoginByPasswordGuesser,
	SSH_Login_From_Interesting_Hostname,
	SSH_Bytecount_Inconsistency,
};

export {
	# Create a new ID for our log stream
	redef enum Log::ID += { SSH };
	type Log: record {
		ts:              time;
		id:              conn_id;
		status:          string &default="";
		direction:       string &default="";
		remote_location: geo_location;
		client:          string &default="";
		server:          string &default="";
		resp_size:       count &default=0;
	};
	# This is the prototype for the event that the logging framework tries
	# to generate if there is a handler for it.
	global log: event(rec: Log);

	const password_guesses_limit = 30 &redef;
	
	# The size in bytes at which the SSH connection is presumed to be
	# successful.
	const authentication_data_size = 5500 &redef;
	
	# The amount of time to remember presumed non-successful logins to build
	# model of a password guesser.
	const guessing_timeout = 30 mins &redef;
	
	# If you want to lookup and log geoip data in the event of a failed login.
	const log_geodata_on_failure = F &redef;

	# The set of countries for which you'd like to throw notices upon successful login
	#   requires Bro compiled with libGeoIP support
	const watched_countries: set[string] = {"RO"} &redef;

	# Strange/bad host names to originate successful SSH logins
	const interesting_hostnames =
			/^d?ns[0-9]*\./ |
			/^smtp[0-9]*\./ |
			/^mail[0-9]*\./ |
			/^pop[0-9]*\./  |
			/^imap[0-9]*\./ |
			/^www[0-9]*\./  |
			/^ftp[0-9]*\./  &redef;

	# This is a table with orig subnet as the key, and subnet as the value.
	const ignore_guessers: table[subnet] of subnet &redef;
	
	# If true, we tell the event engine to not look at further data
	# packets after the initial SSH handshake. Helps with performance
	# (especially with large file transfers) but precludes some
	# kinds of analyses (e.g., tracking connection size).
	const skip_processing_after_detection = F &redef;
	
	# Keeps count of how many rejections a host has had
	global password_rejections: table[addr] of track_count 
		&default=default_track_count
		&write_expire=guessing_timeout;

	# Keeps track of hosts identified as guessing passwords
	# TODO: guessing_timeout doesn't work correctly here.  If a user redefs
	#       the variable, it won't take effect.
	global password_guessers: set[addr] &read_expire=guessing_timeout+1hr;

	# The list of active SSH connections and the associated session info.
	global active_conns: table[conn_id] of Log &read_expire=2mins;
	
	# Configure DPD and the packet filter
	redef capture_filters += { ["ssh"] = "tcp port 22" };
	redef dpd_config += { [ANALYZER_SSH] = [$ports = set(22/tcp)] };
}

function local_filter(rec: record { id: conn_id; } ): bool
	{
	return is_local_addr(rec$id$resp_h);
	}

event bro_init()
{
	# Create the stream.
	# First argument is the ID for the stream.
	# Second argument is the log record type.
	Log::create_stream("SSH", "SSH::Log");
	# Add a default filter that simply logs everything to "ssh.log" using the default writer.
	Log::add_default_filter("SSH");
}


event check_ssh_connection(c: connection, done: bool)
	{
	# If this is no longer a known SSH connection, just return.
	if ( c$id !in active_conns )
		return;

	# If this is still a live connection and the byte count has not
	# crossed the threshold, just return and let the resheduled check happen later.
	if ( !done && c$resp$size < authentication_data_size )
		return;

	# Make sure the server has sent back more than 50 bytes to filter out
	# hosts that are just port scanning.  Nothing is ever logged if the server
	# doesn't send back at least 50 bytes.
	if (c$resp$size < 50)
		return;

	local ssh_log = active_conns[c$id];
	local status = "failure";
	local direction = is_local_addr(c$id$orig_h) ? "to" : "from";
	local location: geo_location;
	
	if ( done && c$resp$size < authentication_data_size )
		{
		# presumed failure
		if ( log_geodata_on_failure )
			location = (direction == "to") ? lookup_location(c$id$resp_h) : lookup_location(c$id$orig_h);

		if ( c$id$orig_h !in password_rejections )
			password_rejections[c$id$orig_h] = default_track_count(c$id$orig_h);
			
		# Track the number of rejections
		if ( !(c$id$orig_h in ignore_guessers &&
		       c$id$resp_h in ignore_guessers[c$id$orig_h]) )
			++password_rejections[c$id$orig_h]$n;

		if ( default_check_threshold(password_rejections[c$id$orig_h]) )
			{
			add password_guessers[c$id$orig_h];
			Notice::NOTICE([$note=SSH_PasswordGuessing,
			        $conn=c,
			        $msg=fmt("SSH password guessing by %s", c$id$orig_h),
			        $sub=fmt("%d failed logins", password_rejections[c$id$orig_h]$n),
			        $n=password_rejections[c$id$orig_h]$n]);
			}
		} 
	# TODO: This is to work around a quasi-bug in Bro which occasionally 
	#       causes the byte count to be oversized.
	#   Watch for Gregors work that adds an actual counter of bytes transferred.
	else if (c$resp$size < 20000000) 
		{ 
		# presumed successful login
		status = "success";
		location = (direction == "to") ? lookup_location(c$id$resp_h) : lookup_location(c$id$orig_h);

		if ( password_rejections[c$id$orig_h]$n > password_guesses_limit &&
		     c$id$orig_h !in password_guessers)
			{
			add password_guessers[c$id$orig_h];
			Notice::NOTICE([$note=SSH_LoginByPasswordGuesser,
			        $conn=c,
			        $n=password_rejections[c$id$orig_h]$n,
			        $msg=fmt("Successful SSH login by password guesser %s", c$id$orig_h),
			        $sub=fmt("%d failed logins", password_rejections[c$id$orig_h]$n)]);
			}

		local message = fmt("SSH login %s %s \"%s\" \"%s\" %f %f %s (triggered with %d bytes)",
		              direction, location$country_code, location$region, location$city,
		              location$latitude, location$longitude,
		              id_string(c$id), c$resp$size);
		# TODO: rewrite the message once a location variable can be put in notices
		Notice::NOTICE([$note=SSH_Login,
		        $conn=c,
		        $msg=message,
		        $sub=location$country_code]);
		
		# Check to see if this login came from an interesting hostname
		when( local hostname = lookup_addr(c$id$orig_h) )
			{
			if ( interesting_hostnames in hostname )
				{
				Notice::NOTICE([$note=SSH_Login_From_Interesting_Hostname,
				        $conn=c,
				        $msg=fmt("Strange login from %s", hostname),
				        $sub=hostname]);
				}
			}
		}
	else if (c$resp$size >= 200000000) 
		{
		Notice::NOTICE([$note=SSH_Bytecount_Inconsistency,
		        $conn=c,
		        $msg="During byte counting in SSH analysis, an overly large value was seen.",
		        $sub=fmt("%d",c$resp$size)]);
		}

	ssh_log$ts = c$start_time;
	ssh_log$id = c$id;
	ssh_log$remote_location = location;
	ssh_log$status = status;
	ssh_log$direction = direction;
	ssh_log$resp_size = c$resp$size;
	
	Log::write("SSH", ssh_log);

	delete active_conns[c$id];
	# Stop watching this connection, we don't care about it anymore.
	if ( skip_processing_after_detection )
		{
		skip_further_processing(c$id);
		set_record_packets(c$id, F);
		}
	}

event connection_state_remove(c: connection)
	{
	event check_ssh_connection(c, T);
	}

event ssh_watcher(c: connection)
	{
	local id = c$id;
	# don't go any further if this connection is gone already!
	if ( !connection_exists(id) )
		{
		delete active_conns[id];
		return;
		}

	event check_ssh_connection(c, F);
	if ( c$id in active_conns )
		schedule +15secs { ssh_watcher(c) };
	}
	
event ssh_client_version(c: connection, version: string)
	{
	if ( c$id in active_conns )
		active_conns[c$id]$client = version;
	}

event ssh_server_version(c: connection, version: string)
	{
	if ( c$id in active_conns )
		active_conns[c$id]$server = version;
	}

event protocol_confirmation(c: connection, atype: count, aid: count)
	{
	if ( atype == ANALYZER_SSH )
		{
		local tmp: Log;
		active_conns[c$id]=tmp;
		schedule +15secs { ssh_watcher(c) };
		}
	}