@load functions
@load notice
@load software

module SMTP;

redef enum Notice::Type += { 
	## Indicates that the server sent a reply mentioning an SMTP block list.
	SMTP_BL_Error_Message, 
	## Indicates the client's address is seen in the block list error message.
	SMTP_BL_Blocked_Host, 
	## When mail seems to originate from a suspicious location.
	SMTP_Suspicious_Origination,
};

redef enum Software::Type += {
	MAIL_CLIENT,
	MAIL_SERVER,
};

redef enum Log::ID += { SMTP };

# Configure DPD
const ports = { 25/tcp, 587/tcp };
redef capture_filters += { ["smtp"] = "tcp port smtp or tcp port 587" };
redef dpd_config += { [ANALYZER_SMTP] = [$ports = ports] };

export {
	type Log: record {
		ts:                time;
		id:                conn_id;
		helo:              string &optional;
		mailfrom:          string &optional;
		rcptto:            set[string] &optional;
		date:              string &optional;
		from:              string &optional;
		to:                set[string] &optional;
		reply_to:          string &optional;
		msg_id:            string &optional;
		in_reply_to:       string &optional;
		subject:           string &optional;
		x_originating_ip:  addr &optional;
		received_from_originating_ip: addr &optional;
		first_received:    string &optional;
		second_received:   string &optional;
		last_reply:        string &optional; # last message the server sent to the client
		files:             set[string] &optional;
		#path:              vector of addr;
		path:              set[addr] &optional;
		is_webmail:        bool &default=F; # This is not being set yet.
		agent:             string &optional;
	};
	
	type Info: record {
		log: Log;
		
		## Indicate if this session is currently transmitting SMTP message 
		## envelope headers.
		in_headers:               bool &default=F;
		## Indicate if the "Received: from" headers are currently being sent.
		in_received_from_headers: bool &default=F;
		## Indicate that the list of "Received: from" headers is finished.
		received_finished:        bool &default=F;
		## Maintain the current header for cases where there is header wrapping.
		current_header:           string &default="";
		## Count the number of individual messages transmitted during this 
		## SMTP session.  Note, this is not the number of recipients, but the
		## number of message bodies transferred.
		messages_transferred:     count &default=0;
	};
	
	# Probably need to remove this for now.
	#redef record connection += { smtp: Info };
	
	## Direction to capture the full "Received from" path.
	##    RemoteHosts - only capture the path until an internal host is found.
	##    LocalHosts - only capture the path until the external host is discovered.
	##    Enabled - always capture the entire path.
	##    Disabled - never capture the path.
	const mail_path_capture = Enabled &redef;
	
	## Places where it's suspicious for mail to originate from.
	##  requires all-capital, two character country codes (e.x. US)
	##  requires libGeoIP support built in.
	const suspicious_origination_countries: set[string] = {} &redef;
	const suspicious_origination_networks: set[subnet] = {} &redef;

	# This matches content in SMTP error messages that indicate some
	# block list doesn't like the connection/mail.
	const bl_error_messages = 
	    /spamhaus\.org\//
	  | /sophos\.com\/security\//
	  | /spamcop\.net\/bl/
	  | /cbl\.abuseat\.org\// 
	  | /sorbs\.net\// 
	  | /bsn\.borderware\.com\//
	  | /mail-abuse\.com\//
	  | /b\.barracudacentral\.com\//
	  | /psbl\.surriel\.com\// 
	  | /antispam\.imp\.ch\// 
	  | /dyndns\.com\/.*spam/
	  | /rbl\.knology\.net\//
	  | /intercept\.datapacket\.net\//
	  | /uceprotect\.net\//
	  | /hostkarma\.junkemailfilter\.com\// &redef;
	
	global active_sessions: table[conn_id] of Info &read_expire=5mins;
	
	global log_smtp: event(rec: Log);
}

event bro_init()
	{
	Log::create_stream(SMTP, [$columns=Log, $ev=log_smtp]);
	Log::add_default_filter(SMTP);
	}
	
function get_empty_log(c: connection): Log
	{
	local tmp: set[string] = set();
	local tmp2: set[string] = set();
	local tmp3: set[string] = set();
	#local tmp4: vector of addr = vector(0.0.0.0);
	local tmp4: set[addr] = set();
	local l: Log = [$ts=network_time(), $id=c$id];
	       #         $rcptto=tmp, $to=tmp2, $files=tmp3, $path=tmp4];
	return l;
	}

function get_smtp_session(c: connection): Info
	{
	if ( c$id in active_sessions )
		return active_sessions[c$id];
	else
		{
		local session: Info = [$log=get_empty_log(c)];
		active_sessions[c$id] = session;
		return session;
		}
	}

function find_address_in_smtp_header(header: string): string
{
	local ips = find_ip_addresses(header);
	# If there are more than one IP address found, return the second.
	if ( |ips| > 1 )
		return ips[2];
	# Otherwise, return the first.
	else if ( |ips| > 0 )
		return ips[1];
	# Otherwise, there wasn't an IP address found.
	else
		return "";
}

function smtp_message(c: connection)
	{
	local session = get_smtp_session(c);
	
	local loc: geo_location;
	local ip: addr;
	if ( session$log?$x_originating_ip )
		{
		ip = session$log$x_originating_ip;
		loc = lookup_location(ip);
		
		if ( loc$country_code in suspicious_origination_countries ||
			 ip in suspicious_origination_networks )
			{
			NOTICE([$note=SMTP_Suspicious_Origination,
				    $msg=fmt("An email originated from %s (%s).", loc$country_code, ip),
				    $sub=fmt("Subject: %s", session$log$subject),
				    $conn=c]);
			}
		if ( session$log?$received_from_originating_ip &&
		     session$log$received_from_originating_ip != session$log$x_originating_ip )
			{
			ip = session$log$received_from_originating_ip;
			loc = lookup_location(ip);

			if ( loc$country_code in suspicious_origination_countries ||
				 ip in suspicious_origination_networks )
				{
				NOTICE([$note=SMTP_Suspicious_Origination,
					    $msg=fmt("An email originated from %s (%s).", loc$country_code, ip),
					    $sub=fmt("Subject: %s", session$log$subject),
						$conn=c]);
				}
			}
		}
		
	
	# If the MUA provided a user-agent string, kick over to the software framework.
	# This is done here so that the "Received: from" path has a chance to be
	# built since that's where the IP address is pulled from.
	# This falls apart a bit in the cases where a webmail client includes the 
	# IP address of the client in a header.  This will be compensated for 
	# later with more comprehensive webmail interface detection.
	if ( session$log?$agent )
		{
		# TODO: put this back when vectors are supported in the logging framework.
		#local s = Software::parse(session$log$agent, session$log$path[|session$log$path|], MAIL_CLIENT);
		#Software::found(c, s);
		}

	Log::write(SMTP, session$log);
	session$log = get_empty_log(c);

	++session$messages_transferred;
	session$in_headers = F;
	session$in_received_from_headers = F;
	session$received_finished = F;
	}
	
event smtp_request(c: connection, is_orig: bool, command: string, arg: string) &priority=1
	{
	local session = get_smtp_session(c);
	local upper_command = to_upper(command);

	# In case this is not the first message in a session we want to 
	# essentially write out a log, clear the session tracking, and begin
	# new session tracking.
	if ( upper_command == "MAIL" && /^[fF][rR][oO][mM]:/ in arg &&
	     session$messages_transferred > 0 )
		{
		local new_helo = session$log$helo;
		smtp_message(c);
		session = get_smtp_session(c);
		session$log$helo = new_helo;

		# TODO: put back when logging framework supports vectors
		# Start off the received from headers with this connection
		#session$log$path[1] = c$id$resp_h;
		#session$log$path[2] = c$id$orig_h;
		}

	if ( upper_command == "HELO" || upper_command == "EHLO" )
		session$log$helo = arg;

	else if ( upper_command == "RCPT" && /^[tT][oO]:/ in arg )
		{
		if ( ! session$log?$rcptto ) 
			{
			local a: set[string] = set();
			session$log$rcptto = a;
			}
		add session$log$rcptto[split1(arg, /:[[:blank:]]*/)[2]];
		}

	else if ( upper_command == "MAIL" && /^[fF][rR][oO][mM]:/ in arg )
		{
		local partially_done = split1(arg, /:[[:blank:]]*/)[2];
		session$log$mailfrom = split1(partially_done, /[[:blank:]]/)[1];
		}
	}
	

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string,
                 msg: string, cont_resp: bool)
	{
	local session = get_smtp_session(c);
	
	# This continually overwrites, but we want the last reply,
	# so this actually works fine.
	if ( code != 421 && code >= 400 )
		{
		session$log$last_reply = fmt("%d %s", code, msg);

		# Raise a notice when an SMTP error about a block list is discovered.
		if ( bl_error_messages in msg )
			{
			local note = SMTP_BL_Error_Message;
			local message = fmt("%s received an error message mentioning an SMTP block list", c$id$orig_h);

			# Determine if the originator's IP address is in the message.
			local ips = find_ip_addresses(msg);
			local text_ip = "";
			if ( |ips| > 0 && to_addr(ips[1]) == c$id$orig_h )
				{
				note = SMTP_BL_Blocked_Host;
				message = fmt("%s is on an SMTP block list", c$id$orig_h);
				}
			
			NOTICE([$note=note,
			        $conn=c,
			        $msg=message,
			        $sub=msg]);
			}
		}
	}

event smtp_data(c: connection, is_orig: bool, data: string) &priority=1
	{
	# Is there something we should be handling from the server?
	if ( ! is_orig ) return;
		
	local session = get_smtp_session(c);

	if ( ! session$in_headers )
		{
		if ( /^[cC][oO][nN][tT][eE][nN][tT]-[dD][iI][sS].*[fF][iI][lL][eE][nN][aA][mM][eE]/ in data )
			{
			if ( ! session$log?$files )
				{
				local a: set[string] = set();
				session$log$files = a;
				}
			data = sub(data, /^.*[fF][iI][lL][eE][nN][aA][mM][eE]=/, "");
			add session$log$files[data];
			}
		return;
		}

	if ( /^[[:blank:]]*$/ in data )
		session$in_headers = F;

	# This is to reconstruct headers that tend to wrap around.
	if ( /^[[:blank:]]/ in data )
		{
		data = sub(data, /^[[:blank:]]/, "");
		if ( session$current_header == "message-id" )
			session$log$msg_id += data;
		else if ( session$current_header == "received" )
			session$log$first_received += data;
		else if ( session$current_header == "in-reply-to" )
			session$log$in_reply_to += data;
		else if ( session$current_header == "subject" )
			session$log$subject += data;
		else if ( session$current_header == "from" )
			session$log$from += data;
		else if ( session$current_header == "reply-to" )
			session$log$reply_to += data;
		else if ( session$current_header == "agent" )
			session$log$agent += data;
		return;
		}
	# Once there isn't a line starting with a blank, we're not continuing a 
	# header anymore.
	session$current_header = "";
	
	local header_parts = split1(data, /:[[:blank:]]*/);
	# TODO: do something in this case?  This would definitely be odd.
	if ( |header_parts| != 2 )
		return;
		
	local header_key = to_upper(header_parts[1]);
	local header_val = header_parts[2];
	
	if ( header_key == "MESSAGE-ID" )
		{
		session$log$msg_id = split1(data, /:[[:blank:]]*/)[2];
		session$current_header = "message-id";
		}
	
	else if ( header_key == "RECEIVED" )
		{
		session$log$second_received = session$log$first_received;
		session$log$first_received = header_val;
		# Fill in the second value in case there is only one hop in the message.
		if ( session$log$second_received == "" )
			session$log$second_received = session$log$first_received;
		
		session$current_header = "received";
		}
	
	else if ( header_key == "IN-REPLY-TO" )
		{
		session$log$in_reply_to = header_val;
		session$current_header = "in-reply-to";
		}
	
	else if ( header_key == "DATE" )
		{
		session$log$date = header_val;
		session$current_header = "date";
		}
	
	else if ( header_key == "FROM" )
		{
		session$log$from = header_val;
		session$current_header = "from";
		}
	
	else if ( header_key == "TO" )
		{
		add session$log$to[header_val];
		session$current_header = "to";
		}
	
	else if ( header_key == "REPLY-TO" )
		{
		session$log$reply_to = header_val;
		session$current_header = "reply-to";
		}
	
	else if ( header_key == "SUBJECT" )
		{
		session$log$subject = header_val;
		session$current_header = "subject";
		}

	else if ( header_key == "X-ORIGINATING-IP" )
		{
		local addresses = find_ip_addresses(header_val);
		if ( |addresses| > 0 )
			session$log$x_originating_ip = to_addr(addresses[1]);
		else
			session$log$x_originating_ip = to_addr(header_val);
		session$current_header = "x-originating-ip";
		}
	
	else if ( header_key == "X-MAILER" || header_key == "USER-AGENT" )
		{
		session$log$agent = header_val;
		session$current_header = "agent";
		}
	}
	
# This event handler builds the "Received From" path by reading the 
# headers in the mail
event smtp_data(c: connection, is_orig: bool, data: string)
	{
	local session = get_smtp_session(c);
	
	# If we've decided that we're done watching the received headers for
	# whatever reason, we're done.  Could be due to only watching until 
	# local addresses are seen in the received from headers.
	if ( session$received_finished )
		return;

	if ( /^[rR][eE][cC][eE][iI][vV][eE][dD]:/ in data ) 
		session$in_received_from_headers = T;
	else if ( /^[[:blank:]]/ !in data )
		session$in_received_from_headers = F;

	if ( session$in_received_from_headers ) # currently seeing received from headers
		{
		local text_ip = find_address_in_smtp_header(data);

		if ( text_ip == "" )
			return;

		local ip = to_addr(text_ip);

		# I don't care if mail bounces around on localhost
		if ( ip == 127.0.0.1 ) return;

		# This overwrites each time.
		session$log$received_from_originating_ip = ip;

		if ( ! addr_matches_hosts(ip, mail_path_capture) && 
		     ip !in private_address_space )
			{
			session$received_finished=T;
			}

		# TODO: put back once vectors can be logged.
		#session$log$path[|session$log$path|+1] = ip;
		if ( ! session$log?$path )
			{
			local a: set[addr] = set();
			session$log$path = a;
			}
		add session$log$path[ip];
		}
	else if ( ! session$in_headers && ! session$received_finished ) 
		session$received_finished=T;
	}

event connection_state_remove(c: connection) &priority=-1
	{
	if ( c$id in active_sessions )
		{
		smtp_message(c);
		delete active_sessions[c$id];
		}
	}
