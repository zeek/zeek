@load base/utils/addrs
@load base/utils/directions-and-hosts
@load base/utils/email
@load base/protocols/conn/removal-hooks

module SMTP;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	type Info: record {
		## Time when the message was first seen.
		ts:                time            &log;
		## Unique ID for the connection.
		uid:               string          &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:                conn_id         &log;
		## A count to represent the depth of this message transaction in
		## a single connection where multiple messages were transferred.
		trans_depth:       count           &log;
		## Contents of the Helo header.
		helo:              string          &log &optional;
		## Email addresses found in the From header.
		mailfrom:          string          &log &optional;
		## Email addresses found in the Rcpt header.
		rcptto:            set[string]     &log &optional;
		## Contents of the Date header.
		date:              string          &log &optional;
		## Contents of the From header.
		from:              string          &log &optional;
		## Contents of the To header.
		to:                set[string]     &log &optional;
		## Contents of the CC header.
		cc:                set[string]     &log &optional;
		## Contents of the ReplyTo header.
		reply_to:          string          &log &optional;
		## Contents of the MsgID header.
		msg_id:            string          &log &optional;
		## Contents of the In-Reply-To header.
		in_reply_to:       string          &log &optional;
		## Contents of the Subject header.
		subject:           string          &log &optional;
		## Contents of the X-Originating-IP header.
		x_originating_ip:  addr            &log &optional;
		## Contents of the first Received header.
		first_received:    string          &log &optional;
		## Contents of the second Received header.
		second_received:   string          &log &optional;
		## The last message that the server sent to the client.
		last_reply:        string          &log &optional;
		## The message transmission path, as extracted from the headers.
		path:              vector of addr  &log &optional;
		## Value of the User-Agent header from the client.
		user_agent:        string          &log &optional;

		## Indicates that the connection has switched to using TLS.
		tls:               bool            &log &default=F;
		## Indicates if the "Received: from" headers should still be
		## processed.
		process_received_from: bool        &default=T;
		## Indicates if client activity has been seen, but not yet logged.
		has_client_activity:  bool            &default=F;
		## Indicates if the SMTP headers should still be processed.
		process_smtp_headers:  bool        &default=T;
		entity_count:	       count	   &default=0;
	};

	type State: record {
		helo:                     string    &optional;
		## Count the number of individual messages transmitted during
		## this SMTP session.  Note, this is not the number of
		## recipients, but the number of message bodies transferred.
		messages_transferred:     count     &default=0;

		pending_messages:         set[Info] &optional;
	};

	## Direction to capture the full "Received from" path.
	##    REMOTE_HOSTS - only capture the path until an internal host is found.
	##    LOCAL_HOSTS - only capture the path until the external host is discovered.
	##    ALL_HOSTS - always capture the entire path.
	##    NO_HOSTS - never capture the path.
	option mail_path_capture = ALL_HOSTS;

	## Create an extremely shortened representation of a log line.
	global describe: function(rec: Info): string;

	global log_smtp: event(rec: Info);

	## SMTP finalization hook.  Remaining SMTP info may get logged when it's called.
	global finalize_smtp: Conn::RemovalHook;
}

redef record connection += {
	smtp:       Info  &optional;
	smtp_state: State &optional;
};

const ports = { 25/tcp, 587/tcp };
redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	Log::create_stream(SMTP::LOG, [$columns=SMTP::Info, $ev=log_smtp, $path="smtp", $policy=log_policy]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_SMTP, ports);
	}

function find_address_in_smtp_header(header: string): string
	{
	local ips = extract_ip_addresses(header, T);
	# If there are more than one IP address found, return the second.
	if ( |ips| > 1 )
		return ips[1];
	# Otherwise, return the first.
	else if ( |ips| > 0 )
		return ips[0];
	# Otherwise, there wasn't an IP address found.
	else
		return "";
	}

function new_smtp_log(c: connection): Info
	{
	local l: Info;
	l$ts=network_time();
	l$uid=c$uid;
	l$id=c$id;
	# The messages_transferred count isn't incremented until the message is
	# finished so we need to increment the count by 1 here.
	l$trans_depth = c$smtp_state$messages_transferred+1;

	if ( c$smtp_state?$helo )
		l$helo = c$smtp_state$helo;

	# The path will always end with the hosts involved in this connection.
	# The lower values in the vector are the end of the path.
	l$path = vector(c$id$resp_h, c$id$orig_h);

	Conn::register_removal_hook(c, finalize_smtp);
	return l;
	}

function set_smtp_session(c: connection)
	{
	if ( ! c?$smtp_state )
		c$smtp_state = [];

	if ( ! c?$smtp )
		c$smtp = new_smtp_log(c);
	}

function smtp_message(c: connection)
	{
	if ( c$smtp$has_client_activity )
		{
		Log::write(SMTP::LOG, c$smtp);
		c$smtp = new_smtp_log(c);
		}
	}

event smtp_request(c: connection, is_orig: bool, command: string, arg: string) &priority=5
	{
	set_smtp_session(c);
	local upper_command = to_upper(command);

	if ( upper_command == "HELO" || upper_command == "EHLO" )
		{
		c$smtp_state$helo = arg;
		c$smtp$helo = arg;
		}

	else if ( upper_command == "RCPT" && /^[tT][oO]:/ in arg )
		{
		if ( ! c$smtp?$rcptto )
			c$smtp$rcptto = set();

		local rcptto_addrs = extract_email_addrs_set(arg);
		for ( rcptto_addr in rcptto_addrs )
			{
			rcptto_addr = gsub(rcptto_addr, /ORCPT=rfc822;?/, "");
			add c$smtp$rcptto[rcptto_addr];
			}

		c$smtp$has_client_activity = T;
		}

	else if ( upper_command == "MAIL" && /^[fF][rR][oO][mM]:/ in arg )
		{
		# Flush last message in case we didn't see the server's acknowledgement.
		smtp_message(c);

		local mailfrom = extract_first_email_addr(arg);
		if ( mailfrom != "" )
			c$smtp$mailfrom = mailfrom;
		c$smtp$has_client_activity = T;
		}
	}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string,
                 msg: string, cont_resp: bool) &priority=5
	{
	set_smtp_session(c);

	# This continually overwrites, but we want the last reply,
	# so this actually works fine.
	c$smtp$last_reply = fmt("%d %s", code, msg);
	}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string,
                 msg: string, cont_resp: bool) &priority=-5
	{
	if ( cmd == "." )
		{
		# Track the number of messages seen in this session.
		++c$smtp_state$messages_transferred;
		smtp_message(c);
		c$smtp = new_smtp_log(c);
		}
	}

event mime_one_header(c: connection, h: mime_header_rec) &priority=5
	{
	if ( ! c?$smtp || ! c$smtp$process_smtp_headers ) return;

	if ( h$name == "MESSAGE-ID" )
		c$smtp$msg_id = h$value;

	else if ( h$name == "RECEIVED" )
		{
		if ( c$smtp?$first_received )
			c$smtp$second_received = c$smtp$first_received;
		c$smtp$first_received = h$value;
		}

	else if ( h$name == "IN-REPLY-TO" )
		c$smtp$in_reply_to = h$value;

	else if ( h$name == "SUBJECT" )
		c$smtp$subject = h$value;

	else if ( h$name == "FROM" )
		c$smtp$from = h$value;

	else if ( h$name == "REPLY-TO" )
		c$smtp$reply_to = h$value;

	else if ( h$name == "DATE" )
		c$smtp$date = h$value;

	else if ( h$name == "TO" )
		{
		if ( ! c$smtp?$to )
			c$smtp$to = set();

		local to_email_addrs = split_mime_email_addresses(h$value);
		for ( to_email_addr in to_email_addrs )
			{
			add c$smtp$to[to_email_addr];
			}
		}

	else if ( h$name == "CC" )
		{
		if ( ! c$smtp?$cc )
			c$smtp$cc = set();

		local cc_parts = split_mime_email_addresses(h$value);
		for ( cc_part in cc_parts )
			add c$smtp$cc[cc_part];
		}

	else if ( h$name == "X-ORIGINATING-IP" )
		{
		local addresses = extract_ip_addresses(h$value);
		if ( 0 in addresses )
			c$smtp$x_originating_ip = to_addr(addresses[0]);
		}

	else if ( h$name == "X-MAILER" ||
	          h$name == "USER-AGENT" ||
	          h$name == "X-USER-AGENT" )
		c$smtp$user_agent = h$value;
	}

# This event handler builds the "Received From" path by reading the
# headers in the mail
event mime_one_header(c: connection, h: mime_header_rec) &priority=3
	{
	# If we've decided that we're done watching the received headers for
	# whatever reason, we're done.  Could be due to only watching until
	# local addresses are seen in the received from headers.
	if ( ! c?$smtp || h$name != "RECEIVED" || ! c$smtp$process_received_from ||
	     ! c$smtp$process_smtp_headers )
		return;

	local text_ip = find_address_in_smtp_header(h$value);
	if ( text_ip == "" )
		return;
	local ip = to_addr(text_ip);

	if ( ! addr_matches_host(ip, mail_path_capture) &&
	     ! Site::is_private_addr(ip) )
		{
		c$smtp$process_received_from = F;
		}
	if ( c$smtp$path[|c$smtp$path|-1] != ip )
		c$smtp$path += ip;
	}

# This event handler sets the flag to stop processing SMTP headers if
# any sub-entity is found.
event mime_begin_entity(c: connection) &priority=5
	{
	if ( c?$smtp )
		{
		++c$smtp$entity_count;

		if ( c$smtp$entity_count > 1 )
			c$smtp$process_smtp_headers = F;
		}
	}

hook finalize_smtp(c: connection)
	{
	if ( c?$smtp )
		smtp_message(c);
	}

event smtp_starttls(c: connection) &priority=5
	{
	if ( c?$smtp )
		{
		c$smtp$tls = T;
		c$smtp$has_client_activity = T;
		}
	}

function describe(rec: Info): string
	{
	if ( rec?$mailfrom && rec?$rcptto )
		{
		local one_to = "";
		for ( email in rec$rcptto )
			{
			one_to = email;
			break;
			}
		local abbrev_subject = "";
		if ( rec?$subject )
			{
			if ( |rec$subject| > 20 )
				{
				abbrev_subject = rec$subject[0:21] + "...";
				}
			}

		return fmt("%s -> %s%s%s", rec$mailfrom, one_to,
			(|rec$rcptto|>1 ? fmt(" (plus %d others)", |rec$rcptto|-1) : ""),
			(abbrev_subject != "" ? fmt(": %s", abbrev_subject) : ""));
		}

	return "";
	}
