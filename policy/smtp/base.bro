@load functions
@load notice
@load software

@load smtp/detect
@load smtp/utils

module SMTP;

redef enum Notice::Type += { 
	## Indicates that the server sent a reply mentioning an SMTP block list.
	SMTP_BL_Error_Message, 
	## Indicates the client's address is seen in the block list error message.
	SMTP_BL_Blocked_Host, 
	## When mail seems to originate from a suspicious location.
	SMTP_Suspicious_Origination,
};

redef enum Log::ID += { SMTP };

export {
	type Info: record {
		ts:                time            &log;
		uid:               string          &log;
		id:                conn_id         &log;
		helo:              string          &log &optional;
		mailfrom:          string          &log &optional;
		rcptto:            set[string]     &log &optional;
		date:              string          &log &optional;
		from:              string          &log &optional;
		to:                set[string]     &log &optional;
		reply_to:          string          &log &optional;
		msg_id:            string          &log &optional;
		in_reply_to:       string          &log &optional;
		subject:           string          &log &optional;
		x_originating_ip:  addr            &log &optional;
		first_received:    string          &log &optional;
		second_received:   string          &log &optional;
		## The last message the server sent to the client.
		last_reply:        string          &log &optional;
		files:             set[string]     &log &optional;
		path:              vector of addr  &log &optional;
		user_agent:        string          &log &optional;
		
		## Indicate if this session is currently transmitting SMTP message 
		## envelope headers.
		in_headers:        bool            &default=F;
		## Indicate if the "Received: from" headers should still be processed.
		process_received_from: bool        &default=T;
		## Maintain the current header for cases where there is header wrapping.
		current_header:    string          &default="";
		## Indicate when the message is logged and no longer applicable.
		done:              bool            &default=F;
	};
	
	type State: record {
		## Count the number of individual messages transmitted during this 
		## SMTP session.  Note, this is not the number of recipients, but the
		## number of message bodies transferred.
		messages_transferred:     count     &default=0;
		
		pending_messages:         set[Info] &optional;
	};
	
	## Direction to capture the full "Received from" path.
	##    RemoteHosts - only capture the path until an internal host is found.
	##    LocalHosts - only capture the path until the external host is discovered.
	##    Enabled - always capture the entire path.
	##    Disabled - never capture the path.
	const mail_path_capture = Enabled &redef;
	
	global log_smtp: event(rec: Info);
}

redef record connection += { 
	smtp:       Info  &optional;
	smtp_state: State &optional;
};

# Configure DPD
const ports = { 25/tcp, 587/tcp };
redef capture_filters += { ["smtp"] = "tcp port smtp or tcp port 587" };
redef dpd_config += { [ANALYZER_SMTP] = [$ports = ports] };

event bro_init()
	{
	Log::create_stream(SMTP, [$columns=SMTP::Info, $ev=log_smtp]);
	}
	
function new_smtp_log(c: connection): Info
	{
	local l: Info;
	l$ts=network_time();
	l$uid=c$uid;
	l$id=c$id;
	if ( c?$smtp && c$smtp?$helo )
		l$helo = c$smtp$helo;
	
	# The path will always end with the hosts involved in this connection.
	# The lower values in the vector are the end of the path.
	l$path = vector(c$id$resp_h, c$id$orig_h);
	
	return l;
	}

function set_smtp_session(c: connection)
	{
	if ( ! c?$smtp || c$smtp$done )
		c$smtp = new_smtp_log(c);
	
	if ( ! c?$smtp_state )
		c$smtp_state = [];
	}


function smtp_message(c: connection)
	{
	Log::write(SMTP, c$smtp);
	c$smtp$done = T;
	}
	
event smtp_request(c: connection, is_orig: bool, command: string, arg: string) &priority=5
	{
	set_smtp_session(c);
	local upper_command = to_upper(command);
	
	# In case this is not the first message in a session we want to 
	# essentially write out a log, clear the session tracking, and begin
	# new session tracking.
	if ( upper_command == "MAIL" && /^[fF][rR][oO][mM]:/ in arg &&
	     c$smtp_state$messages_transferred > 0 )
		{
		smtp_message(c);
		}

	if ( upper_command == "HELO" || upper_command == "EHLO" )
		c$smtp$helo = arg;

	else if ( upper_command == "RCPT" && /^[tT][oO]:/ in arg )
		{
		if ( ! c$smtp?$rcptto ) 
			c$smtp$rcptto = set();
		add c$smtp$rcptto[split1(arg, /:[[:blank:]]*/)[2]];
		
		# This is as good a place as any to increase the message count.
		++c$smtp_state$messages_transferred;
		}

	else if ( upper_command == "MAIL" && /^[fF][rR][oO][mM]:/ in arg )
		{
		local partially_done = split1(arg, /:[[:blank:]]*/)[2];
		c$smtp$mailfrom = split1(partially_done, /[[:blank:]]/)[1];
		}
		
	else if ( upper_command == "DATA" )
		{
		c$smtp$in_headers = T;
		}
	}
	

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string,
                 msg: string, cont_resp: bool) &priority=5
	{
	set_smtp_session(c);
	
	# This continually overwrites, but we want the last reply,
	# so this actually works fine.
	if ( code != 421 && code >= 400 )
		{
		c$smtp$last_reply = fmt("%d %s", code, msg);

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
			
			NOTICE([$note=note, $conn=c, $msg=message, $sub=msg]);
			}
		}
	}

event smtp_data(c: connection, is_orig: bool, data: string) &priority=5
	{
	# Is there something we should be handling from the server?
	if ( ! is_orig ) return;
	
	set_smtp_session(c);
	
	if ( ! c$smtp$in_headers )
		{
		if ( /^[cC][oO][nN][tT][eE][nN][tT]-[dD][iI][sS].*[fF][iI][lL][eE][nN][aA][mM][eE]/ in data )
			{
			if ( ! c$smtp?$files )
				c$smtp$files = set();
			data = sub(data, /^.*[fF][iI][lL][eE][nN][aA][mM][eE]=/, "");
			add c$smtp$files[data];
			}
		return;
		}

	if ( /^[[:blank:]]*$/ in data )
		c$smtp$in_headers = F;

	# This is to reconstruct headers that tend to wrap around.
	if ( /^[[:blank:]]/ in data )
		{
		# Remove all but a single space at the beginning (this seems to follow
		# the most common behavior).
		data = sub(data, /^[[:blank:]]*/, " ");
		if ( c$smtp$current_header == "MESSAGE-ID" )
			c$smtp$msg_id += data;
		else if ( c$smtp$current_header == "RECEIVED" )
			c$smtp$first_received += data;
		else if ( c$smtp$current_header == "IN-REPLY-TO" )
			c$smtp$in_reply_to += data;
		else if ( c$smtp$current_header == "SUBJECCT" )
			c$smtp$subject += data;
		else if ( c$smtp$current_header == "FROM" )
			c$smtp$from += data;
		else if ( c$smtp$current_header == "REPLY-TO" )
			c$smtp$reply_to += data;
		else if ( c$smtp$current_header == "USER-AGENT" )
			c$smtp$user_agent += data;
		return;
		}
	# Once there isn't a line starting with a blank, we're not continuing a 
	# header anymore.
	c$smtp$current_header = "";
	
	local header_parts = split1(data, /:[[:blank:]]*/);
	# TODO: do something in this case?  This would definitely be odd.
	# Header wrapping needs to be handled more elegantly.  This will happen
	# if the header value is wrapped immediately after the header key.
	if ( |header_parts| != 2 )
		return;
	
	local header_key = to_upper(header_parts[1]);
	c$smtp$current_header = header_key;
	
	local header_val = header_parts[2];
	
	if ( header_key == "MESSAGE-ID" )
		c$smtp$msg_id = header_val;
	
	else if ( header_key == "RECEIVED" )
		{
		if ( c$smtp?$first_received )
			c$smtp$second_received = c$smtp$first_received;
		c$smtp$first_received = header_val;
		}
	
	else if ( header_key == "IN-REPLY-TO" )
		c$smtp$in_reply_to = header_val;
	
	else if ( header_key == "DATE" )
		c$smtp$date = header_val;
	
	else if ( header_key == "FROM" )
		c$smtp$from = header_val;
	
	else if ( header_key == "TO" )
		{
		if ( ! c$smtp?$to )
			c$smtp$to = set();
		add c$smtp$to[header_val];
		}
	
	else if ( header_key == "REPLY-TO" )
		c$smtp$reply_to = header_val;
	
	else if ( header_key == "SUBJECT" )
		c$smtp$subject = header_val;

	else if ( header_key == "X-ORIGINATING-IP" )
		{
		local addresses = find_ip_addresses(header_val);
		if ( 1 in addresses )
			c$smtp$x_originating_ip = to_addr(addresses[1]);
		}
	
	else if ( header_key == "X-MAILER" || 
	          header_key == "USER-AGENT" ||
	          header_key == "X-USER-AGENT" )
		{
		c$smtp$user_agent = header_val;
		# Explicitly set the current header here because there are several 
		# headers bulked under this same key.
		c$smtp$current_header = "USER-AGENT";
		}
	}
	
# This event handler builds the "Received From" path by reading the 
# headers in the mail
event smtp_data(c: connection, is_orig: bool, data: string) &priority=3
	{
	# If we've decided that we're done watching the received headers for
	# whatever reason, we're done.  Could be due to only watching until 
	# local addresses are seen in the received from headers.
	if ( c$smtp$current_header != "RECEIVED" ||
	     ! c$smtp$process_received_from )
		return;
		
	local text_ip = find_address_in_smtp_header(data);
	if ( text_ip == "" )
		return;
	local ip = to_addr(text_ip);
	
	if ( ! addr_matches_hosts(ip, mail_path_capture) && 
	     ip !in private_address_space )
		{
		c$smtp$process_received_from = F;
		}
	
	if ( c$smtp$path[|c$smtp$path|-1] != ip )
		c$smtp$path[|c$smtp$path|] = ip;
	}


event connection_state_remove(c: connection) &priority=-5
	{
	if ( c?$smtp && ! c$smtp$done )
		smtp_message(c);
	}
