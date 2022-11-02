##! Implements base functionality for RDP analysis. Generates the rdp.log file.

@load ./consts
@load base/protocols/conn/removal-hooks

module RDP;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

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
		## Status result for the connection.  It's a mix between
		## RDP negotiation failure messages and GCC server create
		## response messages.
		result:                string  &log &optional;
		## Security protocol chosen by the server.
		security_protocol:     string &log &optional;
		## The channels requested by the client
		client_channels:       vector of string &log &optional;

		## Keyboard layout (language) of the client machine.
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

		## If the connection is being encrypted with native
		## RDP encryption, this is the type of cert
		## being used.
		cert_type:             string  &log &optional;
		## The number of certs seen.  X.509 can transfer an
		## entire certificate chain.
		cert_count:            count   &log &default=0;
		## Indicates if the provided certificate or certificate
		## chain is permanent or temporary.
		cert_permanent:        bool    &log &optional;
		## Encryption level of the connection.
		encryption_level:      string  &log &optional;
		## Encryption method of the connection.
		encryption_method:     string  &log &optional;
		};

	## If true, detach the RDP analyzer from the connection to prevent
	## continuing to process encrypted traffic.
	option disable_analyzer_after_detection = F;

	## The amount of time to monitor an RDP session from when it is first
	## identified. When this interval is reached, the session is logged.
	option rdp_check_interval = 10secs;

	## Event that can be handled to access the rdp record as it is sent on
	## to the logging framework.
	global log_rdp: event(rec: Info);

	## RDP finalization hook.  Remaining RDP info may get logged when it's called.
	global finalize_rdp: Conn::RemovalHook;
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

const rdp_ports = { 3389/tcp };
const rdpeudp_ports = { 3389/udp };
redef likely_server_ports += { rdp_ports, rdpeudp_ports };

event zeek_init() &priority=5
	{
	Log::create_stream(RDP::LOG, [$columns=RDP::Info, $ev=log_rdp, $path="rdp", $policy=log_policy]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_RDP, rdp_ports);
	Analyzer::register_for_ports(Analyzer::ANALYZER_RDPEUDP, rdpeudp_ports);
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
		Conn::register_removal_hook(c, finalize_rdp);
		# The RDP session is scheduled to be logged from
		# the time it is first initiated.
		schedule rdp_check_interval { check_record(c) };
		}
	}

event rdp_connect_request(c: connection, cookie: string) &priority=5
	{
	set_session(c);

	c$rdp$cookie = cookie;
	}

event rdp_negotiation_response(c: connection, security_protocol: count) &priority=5
	{
	set_session(c);

	c$rdp$security_protocol = security_protocols[security_protocol];
	}

event rdp_negotiation_failure(c: connection, failure_code: count) &priority=5
	{
	set_session(c);

	c$rdp$result = failure_codes[failure_code];
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
		c$rdp$requested_color_depth = "32bit";
	else
		c$rdp$requested_color_depth = RDP::high_color_depths[data$high_color_depth];
	}

event rdp_client_network_data(c: connection, channels: ClientChannelList)
	{
	set_session(c);

	if ( ! c$rdp?$client_channels )
		c$rdp$client_channels = vector();

	for ( i in channels )
		# Remove the NULs at the end
		c$rdp$client_channels[i] = gsub(channels[i]$name, /\x00+$/, "");

	if ( |channels| > 31 )
		Reporter::conn_weird("RDP_channels_requested_exceeds_max", c, fmt("%s", |channels|));
	}

event rdp_gcc_server_create_response(c: connection, result: count) &priority=5
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

event rdp_server_certificate(c: connection, cert_type: count, permanently_issued: bool) &priority=5
	{
	set_session(c);

	c$rdp$cert_type = RDP::cert_types[cert_type];

	# There are no events for proprietary/RSA certs right
	# now so we manually count this one.
	if ( c$rdp$cert_type == "RSA" )
		++c$rdp$cert_count;

	c$rdp$cert_permanent = permanently_issued;
	}

event rdp_begin_encryption(c: connection, security_protocol: count) &priority=5
	{
	set_session(c);

	if ( ! c$rdp?$result )
		{
		c$rdp$result = "encrypted";
		}

	c$rdp$security_protocol = security_protocols[security_protocol];
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=5
	{
	if ( c?$rdp && f$source == "RDP" )
		{
		# Count up X509 certs.
		++c$rdp$cert_count;
		}
	}

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo) &priority=5
	{
	if ( atype == Analyzer::ANALYZER_RDP )
		{
		set_session(info$c);
		info$c$rdp$analyzer_id = info$aid;
		}
	}

event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo) &priority=5
	{
	# If a protocol violation occurs, then log the record immediately.
	if ( atype == Analyzer::ANALYZER_RDP && info$c?$rdp )
		write_log(info$c);
	}

hook finalize_rdp(c: connection)
	{
	# If the connection is removed, then log the record immediately.
	if ( c?$rdp )
		{
		write_log(c);
		}
	}
