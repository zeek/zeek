# $Id: smtp.bro 5230 2008-01-14 01:38:18Z vern $

@load conn

module SMTP;

export {
	redef enum Notice += { HotEmailRecipient, };

	const process_smtp_relay = F &redef;

	const smtp_log = open_log_file("smtp") &redef;

	# Used to detect relaying.
	const local_mail_addr = /.*@.*lbl.gov/ &redef;

	const hot_recipients = /@/ &redef;

	const smtp_legal_cmds: set[string] = {
		">", "EHLO", "HELO", "MAIL",
		"RCPT", "DATA", ".", "QUIT",
		"RSET", "VRFY", "EXPN", "HELP", "NOOP",
		"SEND",	"SOML", "SAML", "TURN",
		"STARTTLS",
		"BDAT",
		"ETRN",
		"AUTH",
		"***",
	} &redef;

	const smtp_hot_cmds: table[string] of pattern = {
		["MAIL"] = /.*<.*@.*:.*>.*/,	# relay path
		["RCPT"] = /.*<.*@.*:.*>.*/,	# relay path
		["VRFY"] = /.*/,
		["EXPN"] = /.*/,
		["TURN"] = /.*/,
	} &redef;

	const smtp_sensitive_cmds: set[string] = {
		"VRFY", "EXPN", "TURN",
	} &redef;

	const smtp_expected_reply: set[string, count] = {
		[">", 220],
		["EHLO", 250],
		["HELO", 250],
		["MAIL", 250],
		["RCPT", 250],
		["RCPT", 554],	# transaction failed
		["QUIT", 221],
		["DATA", 354],
		[".", 250],	# end of data
		["RSET", 250],
		["VRFY", 250],
		["EXPN", 250],
		["HELP", 250],
		["HELP", 502],	# help command not supported
		["NOOP", 250],
		["AUTH", 334],		# two round authentication
		["AUTH", 235],		# one round authentication
		["AUTH_ANSWER", 334],	# multiple step authentication
		["AUTH_ANSWER", 235],	# authentication successful
		["STARTTLS", 220],	# Willing to do TLS
		["TURN", 502],		# TURN is expected to be rejected
	};

	type smtp_cmd_info: record {
		cmd: string;
		cmd_arg: string;
		reply: count;
		reply_arg: string;
		cont_reply: bool;
		log_reply: bool;
	};

	type smtp_cmd_info_list: table[count] of smtp_cmd_info;

	type smtp_session_info: record {
		id: count;
		connection_id: conn_id;
		external_orig: bool;
		in_data: bool;
		num_cmds: count;
		num_replies: count;
		cmds: smtp_cmd_info_list;
		in_header: bool;
		keep_current_header: bool;	# hack till MIME rewriter ready
		recipients: string;
		subject: string;
		content_hash: string;
		num_lines_in_body: count;
			# lines in RFC 822 body before MIME decoding
		num_bytes_in_body: count;
			# bytes in entity bodies after MIME decoding
		content_gap: bool;	# whether content gap in conversation

		relay_1_rcpt: string;	# external recipients
		relay_2_from: count;	# session id of same recipient
		relay_2_to: count;
		relay_3_from: count;	# session id of same msg id
		relay_3_to: count;
		relay_4_from: count;	# session id of same content hash
		relay_4_to: count;
	};

	global smtp_sessions: table[conn_id] of smtp_session_info;
	global smtp_session_id = 0;

	global new_smtp_session: function(c: connection);
}

redef capture_filters += { ["smtp"] = "tcp port smtp or tcp port 587" };

# DPM configuration.
global smtp_ports = { 25/tcp, 587/tcp } &redef;
redef dpd_config += { [ANALYZER_SMTP] = [$ports = smtp_ports] };

function is_smtp_connection(c: connection): bool
	{
	return c$id$resp_p == smtp;
	}

event bro_init()
	{
	have_SMTP = T;
	}

global add_to_smtp_relay_table: function(session: smtp_session_info);

function new_smtp_command(session: smtp_session_info, cmd: string, arg: string)
	{
	++session$num_cmds;

	local cmd_info: smtp_cmd_info;
	cmd_info$cmd = cmd;
	cmd_info$cmd_arg = arg;
	cmd_info$reply = 0;
	cmd_info$reply_arg = "";
	cmd_info$cont_reply = F;
	cmd_info$log_reply = F;

	session$cmds[session$num_cmds] = cmd_info;
	}

function new_smtp_session(c: connection)
	{
	local session = c$id;
	local new_id = ++smtp_session_id;

	local info: smtp_session_info;
	local cmds: smtp_cmd_info_list;

	info$id = new_id;
	info$connection_id = session;
	info$in_data = F;
	info$num_cmds = 0;
	info$num_replies = 0;
	info$cmds = cmds;
	info$in_header = F;
	info$keep_current_header = T;
	info$external_orig = !is_local_addr(session$orig_h);

	info$subject = "";
	info$recipients = "";
	info$content_hash = "";
	info$num_lines_in_body = info$num_bytes_in_body = 0;
	info$content_gap = F;

	info$relay_1_rcpt = "";
	info$relay_2_from = info$relay_2_to = info$relay_3_from =
		info$relay_3_to = info$relay_4_from = info$relay_4_to = 0;

	new_smtp_command(info, ">", "<connection>");

	smtp_sessions[session] = info;
	append_addl(c, fmt("#%s", prefixed_id(new_id)));

	print smtp_log, fmt("%.6f #%s %s start %s", c$start_time,
			prefixed_id(new_id), id_string(session), info$external_orig ?
			"external" : "internal" );
	}

function smtp_message(session: smtp_session_info, msg: string)
	{
	print smtp_log, fmt("%.6f #%s %s",
			network_time(), prefixed_id(session$id), msg);
	}

function smtp_log_msg(session: smtp_session_info, is_orig: bool, msg: string)
	{
	print smtp_log, fmt("%.6f #%s %s: %s",
				network_time(),
				prefixed_id(session$id),
				directed_id_string(session$connection_id, is_orig),
				msg);
	}

function smtp_log_reject_recipient(session: smtp_session_info, rcpt: string)
	{
	if ( rcpt == "" )
		rcpt = "<none>";

	smtp_message(session, fmt("Recipient addresses rejected: %s", rcpt));
	}

function smtp_log_command(session: smtp_session_info, is_orig: bool,
				msg: string, cmd_info: smtp_cmd_info)
	{
	smtp_log_msg(session, is_orig, fmt("%s: %s(%s)",
					msg, cmd_info$cmd, cmd_info$cmd_arg));
	}

function smtp_log_reply(session: smtp_session_info, is_orig: bool,
			msg: string, cmd_info: smtp_cmd_info)
	{
	smtp_log_msg(session, is_orig, fmt("%s: %s(%s) --> %d(%s)",
					msg,
					cmd_info$cmd, cmd_info$cmd_arg,
					cmd_info$reply, cmd_info$reply_arg));
	}

event smtp_request(c: connection, is_orig: bool, command: string, arg: string)
	{
	local id = c$id;

	if ( id !in smtp_sessions )
		new_smtp_session(c);

	local session = smtp_sessions[id];
	new_smtp_command(session, command, arg);
	local cmd_info = session$cmds[session$num_cmds];

	# Store the command in session record.
	local log_this_cmd = F;

	if ( command in smtp_hot_cmds && arg == smtp_hot_cmds[command] )
		{
		log_this_cmd = T;
		cmd_info$log_reply = T;
		}

	if ( command in smtp_sensitive_cmds )
		{
		log_this_cmd = T;
		cmd_info$log_reply = T;
		}

	if ( log_this_cmd )
		smtp_log_command(session, is_orig, "unusual command", cmd_info);

	if ( command == "DATA" )
		{
		session$in_data = T;
		session$in_header = T;
		}

	else if ( command == "." )
		session$in_data = F;
	}

function check_cmd_info(session: smtp_session_info): bool
	{
	if ( session$num_replies == 0 )
		return T;

	if ( session$num_replies <= session$num_cmds &&
	     session$num_replies in session$cmds )
		return T;

	smtp_message(session, fmt("error: invalid num_replies: %d (num_cmds = %d)",
				session$num_replies, session$num_cmds));
	return F;
	}

function smtp_command_mail(session: smtp_session_info, cmd_info: smtp_cmd_info)
	{
	local tokens = split(cmd_info$cmd_arg, /(<|:|>)*/);

	local i = 0;
	for ( i in tokens )
		smtp_log_msg(session, T, fmt("%d: \"%s\"", i, tokens[i]));
	}

function extract_recipient(session: smtp_session_info, rcpt_cmd_arg: string): string
	{
	local pair: string_array;
	local s: string;

	s = rcpt_cmd_arg;

	pair = split1(s, /<( |\t)*/);
	if ( length(pair) != 2 )
		{
		smtp_message(session, fmt("error: '<' not found in argument to RCPT: %s",
					rcpt_cmd_arg));
		return "";
		}

	s = pair[2];
	# smtp_message(session, fmt("%s<%s", pair[1], pair[2]));

	pair = split1(s, /( |\t)*>/);
	if ( length(pair) != 2 )
		{
		smtp_message(session, fmt("error: '>' not found in argument to RCPT: %s",
					rcpt_cmd_arg));
		return "";
		}

	s = pair[1];
	# smtp_message(session, fmt("%s>%s", pair[1], pair[2]));

	pair = split1(s, /:/);
	if ( length(pair) == 2 )
		{
		smtp_message(session, fmt("RCPT address is source route path: %s",
					rcpt_cmd_arg));
		s = pair[2];
		}

	# Actually the local part of an address might be case-sensitive,
	# but in most cases it is not.

	s = to_lower(s);

	return s;
	}

global check_relay_1: function(session: smtp_session_info, rcpt: string);
global check_relay_2: function(session: smtp_session_info, rcpt: string);

function smtp_command_rcpt(c: connection, session: smtp_session_info,
				cmd_info: smtp_cmd_info)
	{
	local rcpt = extract_recipient(session, cmd_info$cmd_arg);

	if ( cmd_info$reply == 554 )
		smtp_log_reject_recipient(session, rcpt);

	else if ( rcpt != "" )
		{
		smtp_message(session, fmt("recipient: <%s>", rcpt));

		if ( session$recipients != "" )
			session$recipients = cat(session$recipients, ",");

		session$recipients = cat(session$recipients, rcpt);

		if ( process_smtp_relay )
			{
			check_relay_1(session, rcpt);
			check_relay_2(session, rcpt);
			}

		if ( rcpt == hot_recipients )
			{
			local src = session$connection_id$orig_h;
			local dst = session$connection_id$resp_h;

			NOTICE([$note=HotEmailRecipient, $src=src, $conn=c,
				$user=rcpt,
				$msg=fmt("hot email recipient %s -> %s@%s",
					src, rcpt, dst)]);
			}
		}
	}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string,
			msg: string, cont_resp: bool)
	{
	local id = c$id;

	if ( id !in smtp_sessions )
		new_smtp_session(c);

	local session = smtp_sessions[id];
	local new_reply = F;

	# Check entry before indexing.
	if ( ! check_cmd_info(session) )
		return;

	if ( session$num_replies == 0 ||
	     ! session$cmds[session$num_replies]$cont_reply )
		{
		++session$num_replies;
		if ( session$num_replies !in session$cmds )
			{
			smtp_message(session, fmt("error: unmatched reply: %d %s (%s)",
							code, msg, cmd));
			return;
			}

		new_reply = T;
		}

	if ( ! check_cmd_info(session) )
		return;

	local cmd_info = session$cmds[session$num_replies];

	if ( cmd_info$cmd != cmd )
		{
		smtp_message(session,
			fmt("error: command mismatch: %s(%d) %s(%d), %s (%d %s)",
				cmd_info$cmd, session$num_replies,
				session$cmds[session$num_cmds], session$num_cmds,
				cmd, code, msg));
		return;
		}

	cmd_info$reply = code;
	if ( new_reply )
		cmd_info$reply_arg = msg;
	else
		cmd_info$reply_arg = cat(cmd_info$reply_arg, "\r\n", msg);

	cmd_info$cont_reply = cont_resp;

	local log_this_reply = cmd_info$log_reply;

	if ( [cmd, code] !in smtp_expected_reply )
		log_this_reply = T;

	if ( log_this_reply && ! cont_resp )
		smtp_log_reply(session, is_orig, "unusual command/reply", cmd_info);

	#	else if ( cmd == "MAIL" && code == 250 )
	#		smtp_command_mail(session, cmd_info);

	else if ( cmd == "RCPT" )
		{
		if ( code == 250 || code == 554 )
			smtp_command_rcpt(c, session, cmd_info);
		}

	else if ( cmd == "STARTTLS" && code == 220 )
		{ # it'll now go encrypted - no more we can do.
		skip_further_processing(c$id);
		smtp_message(session, cmd);
		}
	}

function reset_on_gap(session: smtp_session_info)
	{
	local i: count;

	clear_table(session$cmds);

	session$num_cmds = session$num_replies = 0;
	session$in_data = F;
	}

event smtp_unexpected(c: connection, is_orig: bool, msg: string, detail: string)
	{
	local id = c$id;

	if ( id !in smtp_sessions )
		new_smtp_session(c);

	local session = smtp_sessions[id];

	smtp_log_msg(session, is_orig, fmt("unexpected: %s: %s", msg, detail));
	}

function clear_smtp_session(session: smtp_session_info)
	{
	clear_table(session$cmds);
	}

event content_gap(c: connection, is_orig: bool, seq: count, length: count)
	{
	if ( is_smtp_connection(c) )
		{
		local id = c$id;
		if ( id !in smtp_sessions )
			new_smtp_session(c);
		local session = smtp_sessions[id];
		session$content_gap = T;
		reset_on_gap(session);
		}
	}

event connection_finished(c: connection)
	{
	local id = c$id;
	if ( id in smtp_sessions )
		{
		local session = smtp_sessions[id];
		smtp_message(session, "finish");
		clear_smtp_session(session);
		delete smtp_sessions[id];
		}
	}

event connection_state_remove(c: connection)
	{
	local id = c$id;
	if ( id in smtp_sessions )
		{
		local session = smtp_sessions[id];
		smtp_message(session, "state remove");
		clear_smtp_session(session);
		delete smtp_sessions[id];
		}
	}

global rewrite_smtp_header_line:
	function(c: connection, is_orig: bool,
			session: smtp_session_info, line: string);

function smtp_header_line(c: connection, is_orig: bool,
				session: smtp_session_info, line: string)
	{
	if ( rewriting_smtp_trace )
		rewrite_smtp_header_line(c, is_orig, session, line);
	}

function smtp_body_line(c: connection, is_orig: bool,
			session: smtp_session_info, line: string)
	{
	++session$num_lines_in_body;
	session$num_bytes_in_body =
		session$num_bytes_in_body + byte_len(line) + 2; # including CRLF
	}

event smtp_data(c: connection, is_orig: bool, data: string)
	{
	local id = c$id;
	if ( id in smtp_sessions )
		{
		local session = smtp_sessions[id];
		# smtp_log_msg(session, is_orig, fmt("data: %s", data));
		if ( session$in_header )
			{
			if ( data == "" )
				{
				session$in_header = F;
				skip_smtp_data(c);
				}
			else
				{
				smtp_header_line(c, is_orig, session, data);
				# smtp_log_msg(session, T, fmt("header: %s", data));
				}
			}
		else
			{
			# smtp_body_line(c, is_orig, session, data);
			}
		}
	}

event bro_done()
	{
	clear_table(smtp_sessions);
	}
