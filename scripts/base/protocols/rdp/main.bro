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
                cookie: string &log &optional;
                ## Keyboard layout (language) of the client machine.
                keyboard_layout:        string &log &optional;
		## RDP client version used by the client machine.
		client_build:		string &log &optional;
                ## Hostname of the client machine.
                client_hostname:	string &log &optional;
                ## Product ID of the client machine.
                client_product_id:	string &log &optional;
		## Name of the server.
		server_name:		vector of string &log &optional;
                ## Authentication result for the connection. This value is extracted from the payload for native authentication.
		## TODO: Perform heuristic authentication determination for NLA.
                authentication_result: 	string  &log    &optional;
                ## Encryption level of the connection.
                encryption_level:       string  &log    &optional;
                ## Encryption method of the connection. 
                encryption_method:      string  &log    &optional;
		## Track status of logging RDP connections.
		done:			bool &default=F;
        };

	## Variable to track if NTLM authentication is used.
	global ntlm = F;

	## Size in bytes of data sent by the server at which the RDP connection is presumed to be successful (NTLM authentication only).
	const authentication_data_size = 1000 &redef;

        ## Event that can be handled to access the rdp record as it is sent on
        ## to the loggin framework.
        global log_rdp: event(rec: Info);
}

const ports = { 3389/tcp };
redef likely_server_ports += { ports };

event bro_init() &priority=5
        {
        Log::create_stream(RDP::LOG, [$columns=Info, $ev=log_rdp]);
        Analyzer::register_for_ports(Analyzer::ANALYZER_RDP, ports);
        }

redef record connection += {
        rdp: Info &optional;
	};

function rdp_done(c: connection, done: bool)
	{
	if ( done )
	  {
	  c$rdp$done = T;

	  # Not currently implemented
#	  if ( ntlm && use_conn_size_analyzer ) 
#	    {
#	    if ( c$resp$size > authentication_data_size )
#	      c$rdp$authentication_result = "Success (H)";
#	    else c$rdp$authentication_result = "Undetermined";
#	    }

	  if ( c$rdp?$authentication_result && ( ! c$rdp?$encryption_method || ! c$rdp?$encryption_level ) )
	    Reporter::error(fmt("Error parsing RDP security data in connection %s",c$uid));

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

	# schedule the event to run again if necessary
        schedule +5secs { rdp_tracker(c) };
	}

function set_session(c: connection)
        {
        if ( ! c?$rdp )
          {
          c$rdp = [$ts=network_time(),$id=c$id,$uid=c$uid];
          add c$service["rdp"];
          }
        }

event connection_state_remove(c: connection) &priority=-5
	{
	# Log the RDP connection if the connection is removed but the session has not been marked as done
	if ( c?$rdp && ! c$rdp$done )
	  rdp_done(c,T);
	}

event rdp_native_client_request(c: connection, cookie: string) &priority=5
	{
	if ( "Cookie" in clean(cookie) )
	  {
	  set_session(c);
	  local cookie_val = sub(cookie,/Cookie.*\=/,"");
	  c$rdp$cookie = sub(cookie_val,/\x0d\x0a.*$/,"");

	  schedule +5secs { rdp_tracker(c) };
	  }
	}

event rdp_native_client_info(c: connection, keyboard_layout: count, build: count, hostname: string, product_id: string) &priority=5
	{
	set_session(c);
	c$rdp$keyboard_layout = languages[keyboard_layout];
	c$rdp$client_build = builds[build];
	c$rdp$client_hostname = gsub(cat(hostname),/\\0/,""); 
	c$rdp$client_product_id = gsub(cat(product_id),/\\0/,"");

	schedule +5secs { rdp_tracker(c) };
	}

event rdp_native_authentication(c: connection, result: count) &priority=5
	{
        set_session(c);
        c$rdp$authentication_result = results[result];

	schedule +5secs { rdp_tracker(c) };
	}

event rdp_native_server_security(c: connection, encryption_method: count, encryption_level: count, random: string, certificate: string) &priority=5
	{
	set_session(c);
	c$rdp$encryption_method = encryption_methods[encryption_method];
	c$rdp$encryption_level = encryption_levels[encryption_level];

	schedule +5secs { rdp_tracker(c) };
	}

event rdp_ntlm_client_request(c: connection, server: string) &priority=5
        {
        set_session(c);
        ntlm = T;

	if ( ! c$rdp?$server_name )
	  c$rdp$server_name = vector();
        c$rdp$server_name[|c$rdp$server_name|] = server;

	schedule +5secs { rdp_tracker(c) };
        }

event rdp_ntlm_server_response(c: connection, server: string) &priority=5
	{
	set_session(c);
	ntlm = T;

        if ( ! c$rdp?$server_name )
          c$rdp$server_name = vector();
        c$rdp$server_name[|c$rdp$server_name|] = server;

	schedule +5secs { rdp_tracker(c) };
	}

event rdp_debug(c: connection, remainder: string)
	{
	Reporter::error(fmt("Debug RDP data generated in connection %s: %s",c$uid,remainder));
	}
