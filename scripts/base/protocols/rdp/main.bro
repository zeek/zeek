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
		## Track status of logging RDP connections.
		done:			bool 	&default=F;
        };

        ## Event that can be handled to access the rdp record as it is sent on
        ## to the loggin framework.
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

function set_session(c: connection)
        {
        if ( ! c?$rdp )
          {
          c$rdp = [$ts=network_time(),$id=c$id,$uid=c$uid];
	  # Need to do this manually because the DPD framework does not seem to register the protocol (even though DPD is working)
          add c$service["rdp"];
          }
        }

function rdp_done(c: connection, done: bool)
	{
	if ( done )
	  {
	  c$rdp$done = T;

	  Log::write(RDP::LOG, c$rdp);
	  skip_further_processing(c$id);
	  set_record_packets(c$id, F);
	  }
	}

event rdp_tracker(c: connection)
	{
	if ( c$rdp$done )
	  return;

	local id = c$id;
	  
	if ( ! connection_exists(id) )
	  {
	  rdp_done(c,T);
	  return;
	  }

	lookup_connection(id);
	
	if ( connection_exists(id) )
	  {
	  # If the RDP connection has been alive for more than 5secs, log it
	  # This duration should be sufficient to collect the data that needs to be logged
	  local diff = network_time() - c$rdp$ts;
	  if ( diff > 5secs ) 
	    {
	    rdp_done(c,T);
            return;
	    }
	  }

	# Schedule the event to run again if necessary
        schedule +5secs { rdp_tracker(c) };
	}

event connection_state_remove(c: connection) &priority=-5
	{
	# Log the RDP connection if the connection is removed but the session has not been marked as done
	if ( c?$rdp && ! c$rdp$done )
	  rdp_done(c,T);
	}

event rdp_client_request(c: connection, cookie: string) &priority=5
	{
	if ( "Cookie" in clean(cookie) )
	  {
	  set_session(c);
	  local cookie_val = sub(cookie,/Cookie.*\=/,"");
	  c$rdp$cookie = sub(cookie_val,/\x0d\x0a.*$/,"");

	  schedule +5secs { rdp_tracker(c) };
	  }
	}

event rdp_client_data(c: connection, keyboard_layout: count, build: count, hostname: string, product_id: string) &priority=5
	{
	set_session(c);
	c$rdp$keyboard_layout = languages[keyboard_layout];
	c$rdp$client_build = builds[build];
	c$rdp$client_hostname = gsub(cat(hostname),/\\0/,""); 
	c$rdp$client_product_id = gsub(cat(product_id),/\\0/,"");

	schedule +5secs { rdp_tracker(c) };
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
