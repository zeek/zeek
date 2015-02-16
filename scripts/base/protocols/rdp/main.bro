@load ./consts

module RDP;

export {
        redef enum Log::ID += { LOG };

        type Info: record {
                ## Timestamp for when the event happened.
                ts:     		time    &log;
                ## Unique ID for the connection.
                uid:    		string  &log;
                ## The connection's 4-tuple of endpoint addresses/ports.
                id:     		conn_id &log;
                ## Cookie value used by the client machine.
                ## This is typically a username.
                cookie: 		string 	&log &optional;
                ## Keyboard layout (language) of the client machine.
                keyboard_layout:        string 	&log &optional;
		## RDP client version used by the client machine.
		client_build:		string 	&log &optional;
                ## Hostname of the client machine.
                client_hostname:	string 	&log &optional;
                ## Product ID of the client machine.
                client_product_id:	string 	&log &optional;
                ## GCC result for the connection. 
                result: 		string  &log &optional;
                ## Encryption level of the connection.
                encryption_level:       string  &log &optional;
                ## Encryption method of the connection. 
                encryption_method:      string  &log &optional;

		## The analyzer ID used for the analyzer instance attached
		## to each connection.  It is not used for logging since it's a
		## meaningless arbitrary number.
		analyzer_id:      count            &optional;
		## Track status of logging RDP connections.
		done:			bool 	&default=F;
        };

	## If true, detach the RDP analyzer from the connection to prevent
	## continuing to process encrypted traffic. Helps with performance
	## (especially with large file transfers).
	const disable_analyzer_after_detection = T &redef;

	## The amount of time to monitor an RDP session from when it is first 
	## identified. When this interval is reached, the session is logged.
	const rdp_interval = 10secs &redef;

        ## Event that can be handled to access the rdp record as it is sent on
        ## to the logging framework.
        global log_rdp: event(rec: Info);
}

redef record connection += {
        rdp: Info &optional;
        };

const ports = { 3389/tcp };
redef likely_server_ports += { ports };

event bro_init() &priority=5
        {
        Log::create_stream(RDP::LOG, [$columns=Info, $ev=log_rdp]);
        Analyzer::register_for_ports(Analyzer::ANALYZER_RDP, ports);
        }

# Verify that the RDP session contains
# RDP data before writing it to the log. 
function verify_rdp(c: connection)
	{
	local info = c$rdp;
	if ( info?$cookie || info?$keyboard_layout || info?$result )
	  Log::write(RDP::LOG,info);
	else
	  Reporter::error("RDP analyzer was initialized but no data was found");
	}

event log_record(c: connection, remove_analyzer: bool)
        {
	# If the record was logged, then stop processing.
        if ( c$rdp$done )
          return;

	# If the analyzer is no logger attached, then 
	# log the record and stop processing.
	if ( ! remove_analyzer )
	  {
	  c$rdp$done = T;
	  verify_rdp(c);
	  return;
	  }

	# If the value rdp_interval has passed since the 
	# RDP session was started, then log the record. 
        local diff = network_time() - c$rdp$ts;
        if ( diff > rdp_interval )
          {
          c$rdp$done = T;
	  verify_rdp(c);

	  # Remove the analyzer if it is still attached.
          if ( remove_analyzer && disable_analyzer_after_detection && connection_exists(c$id) && c$rdp?$analyzer_id )
            {
            disable_analyzer(c$id, c$rdp$analyzer_id);
            delete c$rdp$analyzer_id;
            }

	  return;
          }
	# If the analyzer is attached and the duration
	# to monitor the RDP session was not met, then
	# reschedule the logging event.
        else
          schedule +rdp_interval { log_record(c,remove_analyzer) };
        }

function set_session(c: connection)
        {
        if ( ! c?$rdp )
	  {
          c$rdp = [$ts=network_time(),$id=c$id,$uid=c$uid];
	  # The RDP session is scheduled to be logged from
	  # the time it is first initiated.
	  schedule +rdp_interval { log_record(c,T) };	
	  }
        }

event rdp_client_request(c: connection, cookie: string) &priority=5
	{
	set_session(c);
	c$rdp$cookie = cookie;
	}

event rdp_client_data(c: connection, keyboard_layout: count, build: count, hostname: string, product_id: string) &priority=5
	{
	set_session(c);
	c$rdp$keyboard_layout = languages[keyboard_layout];
	c$rdp$client_build = builds[build];
	c$rdp$client_hostname = gsub(cat(hostname),/\\0/,""); 
	c$rdp$client_product_id = gsub(cat(product_id),/\\0/,"");
	}

event rdp_result(c: connection, result: count) &priority=5
	{
        set_session(c);
        c$rdp$result = results[result];
	}

event rdp_server_security(c: connection, encryption_method: count, encryption_level: count) &priority=5
	{
	set_session(c);
	c$rdp$encryption_method = encryption_methods[encryption_method];
	c$rdp$encryption_level = encryption_levels[encryption_level];
	}

event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=5
	{
	if ( atype == Analyzer::ANALYZER_RDP )
		{
		set_session(c);
		c$rdp$analyzer_id = aid;
		}
	}

event protocol_violation(c: connection, atype: Analyzer::Tag, aid: count, reason: string) &priority=5
	{
	# If a protocol violation occurs, then log the record immediately.
	if ( c?$rdp )
	  schedule +0secs { log_record(c,F) };
	}

event connection_state_remove(c: connection) &priority=-5
        {
	# If the connection is removed, then log the record immediately.
        if ( c?$rdp )
          schedule +0secs { log_record(c,F) };
        }
