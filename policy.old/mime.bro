# $Id: mime.bro 6724 2009-06-07 09:23:03Z vern $

@load smtp

module MIME;

export {
	const mime_log = open_log_file("mime") &redef;

	type mime_session_info: record {
		id: count;
		connection_id: conn_id;
		smtp_session: SMTP::smtp_session_info;
		level: count;
		data_offset: count;
		content_hash: string;
	};

	global get_session:
		function(c: connection, new_session_ok: bool): mime_session_info;
}

function mime_header_default_handler(session: mime_session_info,
					name: string, arg: string)
	{
	}

type mime_header_handler_func:
	function(session: mime_session_info, name: string, arg: string);

type mime_header_handler_table: table[string] of mime_header_handler_func;

export {
	global mime_header_handler: mime_header_handler_table &redef &default
	= function(name: string): mime_header_handler_func
		{
		# This looks a little weird, but there is no other way
		# to specify a function as the default *value*
		return mime_header_default_handler;
		};
}

global mime_session_id = 0;
global mime_sessions: table[conn_id] of mime_session_info;

function mime_session_string(session: mime_session_info): string
	{
	return fmt("#%s %s +%d", prefixed_id(session$id),
			id_string(session$connection_id), session$level);
	}

function mime_log_warning(what: string)
	{
	print mime_log, fmt("%.6f warning: %s", network_time(), what);
	}

function mime_log_msg(session: mime_session_info, where: string, what: string)
	{
	print mime_log, fmt("%.6f %s: [%s] %s",
				network_time(),
				mime_session_string(session),
				where,
				what);
	}

function mime_header_subject(session: mime_session_info,
				name: string, arg: string)
	{
	if ( session$level == 1 )
		session$smtp_session$subject = arg;
	}


### This is a bit clunky.  These are functions we call out to, defined
# elsewhere.  The way we really ought to do this is to have them passed
# in during initialization.  But for now, we presume knowledge of their
# names in global scope.
module GLOBAL;
global check_relay_3:
	function(session: MIME::mime_session_info, msg_id: string);
global check_relay_4:
	function(session: MIME::mime_session_info, content_hash: string);
module MIME;

function mime_header_message_id(session: mime_session_info, name: string, arg: string)
	{
	local s = arg;

	local t = split1(s, /</);
	if ( length(t) != 2 )
		{
		mime_log_msg(session, "event",
			fmt("message id does not contain '<': %s", arg));
		return;
		}

	s = t[2];

	t = split1(s, />/);
	if ( length(t) != 2 )
		{
		mime_log_msg(session, "event",
			fmt("message id does not contain '>': %s", arg));
		return;
		}

	s = t[1];

	if ( session$level == 1 && SMTP::process_smtp_relay )
		check_relay_3(session, s);
	}

redef mime_header_handler = {
	["SUBJECT"] = mime_header_subject,
	["MESSAGE-ID"] = mime_header_message_id,
};

function new_mime_session(c: connection)
	{
	local id = c$id;
	local session_id = ++mime_session_id;
	local info: mime_session_info;

	info$id = session_id;
	info$connection_id = id;
	info$level = 0;
	info$data_offset = 0;
	info$content_hash = "";

	if ( id !in SMTP::smtp_sessions )
		SMTP::new_smtp_session(c);

	info$smtp_session = SMTP::smtp_sessions[id];

	mime_sessions[id] = info;
	mime_log_msg(info, "start", "");
	}

function get_session(c: connection, new_session_ok: bool): mime_session_info
	{
	local id = c$id;

	if ( id !in mime_sessions )
		{
		if ( ! new_session_ok )
			mime_log_warning(fmt("begin_entity missing for new MIME session %s", id_string(id)));

		new_mime_session(c);
		}

	return mime_sessions[id];
	}

function end_mime_session(session: mime_session_info)
	{
	mime_log_msg(session, "finish", "");
	delete mime_sessions[session$connection_id];
	}

event connection_state_remove(c: connection)
	{
	local id = c$id;

	if ( id in mime_sessions )
		{
		mime_log_msg(mime_sessions[id], "state remove", "");
		delete mime_sessions[id];
		}
	}

function do_mime_begin_entity(c: connection)
	{
	local session = get_session(c, T);

	++session$level;
	session$data_offset = 0;
	mime_log_msg(session, "begin entity", "");
	}

event mime_begin_entity(c: connection)
	{
	do_mime_begin_entity(c);
	}

function do_mime_end_entity(c: connection)
	{
	local session = get_session(c, T);

	mime_log_msg(session, "end entity", "");

	session$smtp_session$num_bytes_in_body =
		session$smtp_session$num_bytes_in_body + session$data_offset;

	if ( session$level > 0 )
		{
		--session$level;
		if ( session$level == 0 )
			end_mime_session(session);
		}
	else
		mime_log_warning(fmt("unmatched end_entity for MIME session %s",
					mime_session_string(session)));
	}

event mime_end_entity(c: connection)
	{
	do_mime_end_entity(c);
	}

event mime_next_entity(c: connection)
	{
	do_mime_end_entity(c);
	do_mime_begin_entity(c);
	}

# event mime_one_header(c: connection, h: mime_header_rec)
#	{
#	local session = get_session(c, T);
#	mime_log_msg(session, "header",
#			fmt("%s: \"%s\"", h$name, h$value));
#	mime_header_handler[h$name](session, h$name, h$value);
#	}

event mime_all_headers(c: connection, hlist: mime_header_list)
	{
	local session = get_session(c, T);
	local i = 0;

	for ( i in hlist )
		{
		local h = hlist[i];
		mime_log_msg(session, "header",
				fmt("%s: \"%s\"", h$name, h$value));
		mime_header_handler[h$name](session, h$name, h$value);
		}
	}

event mime_segment_data(c: connection, length: count, data: string)
	{
	local session = get_session(c, T);

	if ( session$data_offset < 256 )
		mime_log_msg(session, "data", fmt("%d: %s", length, data));

	session$data_offset = session$data_offset + length;
	}

# event mime_entity_data(c: connection, length: count, data: string)
# 	{
#  	local session = get_session(c, T);
#
# 	mime_log_msg(session, "data", fmt("%d: %s", length, sub_bytes(data, 0, 256)));
# 	}

event mime_event(c: connection, event_type: string, detail: string)
	{
	local session = get_session(c, T);
	mime_log_msg(session, "event", fmt("%s: %s", event_type, detail));
	}
