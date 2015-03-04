@load ./consts

module RDP;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp for when the event happened.
		ts:                    time    &log;
		## Unique ID for the connection.
		uid:                   string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:                    conn_id &log;
		## Cookie value used by the client machine.
		## This is typically a username.
		cookie:                string  &log &optional;
		## Keyboard layout     (language) of the client machine.
		keyboard_layout:       string  &log &optional;
		## RDP client version used by the client machine.
		client_build:          string  &log &optional;
		## Name of the client machine.
		client_name:           string  &log &optional;
		## Product ID of the client machine.
		client_dig_product_id: string  &log &optional;
		## Desktop width of the client machine.
		desktop_width:         count   &log &optional;
		## Desktop height of the client machine.
		desktop_height:        count   &log &optional;
		## The color depth requested by the client in 
		## the high_color_depth field.
		requested_color_depth: string  &log &optional;
		## GCC result for the connection. 
		result:                string  &log &optional;
		## Encryption level of the connection.
		encryption_level:      string  &log &optional;
		## Encryption method of the connection. 
		encryption_method:     string  &log &optional;
		## Flag the connection if it was seen over SSL.
                ssl:                    bool    &log &default=F;
		};

	## If true, detach the RDP analyzer from the connection to prevent
	## continuing to process encrypted traffic.
	const disable_analyzer_after_detection = F &redef;

	## The amount of time to monitor an RDP session from when it is first 
	## identified. When this interval is reached, the session is logged.
	const rdp_check_interval = 10secs &redef;

	## Event that can be handled to access the rdp record as it is sent on
	## to the logging framework.
	global log_rdp: event(rec: Info);
}

# Internal fields that aren't useful externally
redef record Info += {
	## The analyzer ID used for the analyzer instance attached
	## to each connection.  It is not used for logging since it's a
	## meaningless arbitrary number.
	analyzer_id: count &optional;
	## Track status of logging RDP connections.
	done:        bool  &default=F;
};

redef record connection += {
	rdp: Info &optional;
};

const ports = { 3389/tcp };
redef likely_server_ports += { ports };

event bro_init() &priority=5
	{
	Log::create_stream(RDP::LOG, [$columns=RDP::Info, $ev=log_rdp]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_RDP, ports);
	}

function write_log(c: connection)
	{
	local info = c$rdp;
	if ( info$done )
		return;

	# Mark this record as fully logged and finished.
	info$done = T;

	# Verify that the RDP session contains
	# RDP data before writing it to the log. 
	if ( info?$cookie || info?$keyboard_layout || info?$result )
		Log::write(RDP::LOG, info);
	}

event check_record(c: connection)
	{
	# If the record was logged, then stop processing.
	if ( c$rdp$done )
		return;

	# If the value rdp_check_interval has passed since the 
	# RDP session was started, then log the record. 
	local diff = network_time() - c$rdp$ts;
	if ( diff > rdp_check_interval )
		{
		write_log(c);

		# Remove the analyzer if it is still attached.
		if ( disable_analyzer_after_detection && 
		     connection_exists(c$id) && 
		     c$rdp?$analyzer_id )
			{
			disable_analyzer(c$id, c$rdp$analyzer_id);
			}

		return;
		}
	else
		{
		# If the analyzer is attached and the duration
		# to monitor the RDP session was not met, then
		# reschedule the logging event.
		schedule rdp_check_interval { check_record(c) };
		}
	}

function set_session(c: connection)
	{
	if ( ! c?$rdp )
		{
		c$rdp = [$ts=network_time(),$id=c$id,$uid=c$uid];
		# The RDP session is scheduled to be logged from
		# the time it is first initiated.
		schedule rdp_check_interval { check_record(c) };
		}
	}

event rdp_client_request(c: connection, cookie: string) &priority=5
	{
	set_session(c);

	c$rdp$cookie = cookie;
	}

event rdp_client_core_data(c: connection, data: RDP::ClientCoreData) &priority=5
	{
	set_session(c);

	c$rdp$keyboard_layout       = RDP::languages[data$keyboard_layout];
	c$rdp$client_build          = RDP::builds[data$client_build];
	c$rdp$client_name           = data$client_name;
	c$rdp$client_dig_product_id = data$dig_product_id;
	c$rdp$desktop_width         = data$desktop_width;
	c$rdp$desktop_height        = data$desktop_height;
	if ( data?$ec_flags && data$ec_flags$want_32bpp_session )
		c$rdp$requested_color_depth = "32-bit";
	else
		c$rdp$requested_color_depth = RDP::high_color_depths[data$high_color_depth];
	}

event rdp_result(c: connection, result: count) &priority=5
	{
	set_session(c);

	c$rdp$result = RDP::results[result];
	}

event rdp_server_security(c: connection, encryption_method: count, encryption_level: count) &priority=5
	{
	set_session(c);

	c$rdp$encryption_method = RDP::encryption_methods[encryption_method];
	c$rdp$encryption_level = RDP::encryption_levels[encryption_level];
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	Files::add_analyzer(f, Files::ANALYZER_X509);
	# always calculate hashes. They are not necessary for base scripts
	# but very useful for identification, and required for policy scripts
	Files::add_analyzer(f, Files::ANALYZER_MD5);
	Files::add_analyzer(f, Files::ANALYZER_SHA1);
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
		write_log(c);
	}
	
event ssl_established(c: connection) &priority=-5
        {
        if ( c?$rdp )
                {
                c$rdp$ssl = T;
                write_log(c);
                }
        }

event connection_state_remove(c: connection) &priority=-5
	{
	# If the connection is removed, then log the record immediately.
	if ( c?$rdp )
		{
		write_log(c);
		}
	}
