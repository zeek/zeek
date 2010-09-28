# $Id: mime-pop.bro 4758 2007-08-10 06:49:23Z vern $
#
# A stripped-down version of mime.bro adapted to work on POP3 events.
#
# FIXME: What's the best way to merge mime.bro and mime-pop3.bro?

@load pop3

module MIME_POP3;
	
const mime_log = open_log_file("mime-pop") &redef;

type mime_session_info: record {
	id: count;
	connection_id: conn_id;
	level: count;
	data_offset: count;
};

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

function new_mime_session(c: connection)
	{
	local id = c$id;
	local session_id = ++mime_session_id;
	local info: mime_session_info;

	info$id = session_id;
	info$connection_id = id;
	info$level = 0;
	info$data_offset = 0;

	mime_sessions[id] = info;
	mime_log_msg(info, "start", "");
	}

function get_mime_session(c: connection, new_session_ok: bool): mime_session_info
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
	if ( c$id$resp_p != 110/tcp )
		return;
	
	local id = c$id;

	if ( id in mime_sessions )
		{
		mime_log_msg(mime_sessions[id], "state remove", "");
		delete mime_sessions[id];
		}
	}

function do_mime_begin_entity(c: connection)
	{
	local session = get_mime_session(c, T);

	++session$level;
	session$data_offset = 0;
	mime_log_msg(session, "begin entity", "");
	}

event mime_begin_entity(c: connection)
	{
	if ( c$id$resp_p != 110/tcp )
		return;
	
	do_mime_begin_entity(c);
	}

function do_mime_end_entity(c: connection)
	{
	local session = get_mime_session(c, T);

	mime_log_msg(session, "end entity", "");

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
	if ( c$id$resp_p != 110/tcp )
		return;
	
	do_mime_end_entity(c);
	}

event mime_next_entity(c: connection)
	{
	if ( c$id$resp_p != 110/tcp )
		return;
	
	do_mime_end_entity(c);
	do_mime_begin_entity(c);
	}

event mime_all_headers(c: connection, hlist: mime_header_list)
	{
	if ( c$id$resp_p != 110/tcp )
		return;
	
	local session = get_mime_session(c, T);
	local i = 0;

	for ( i in hlist )
		{
		local h = hlist[i];
		mime_log_msg(session, "header",
				fmt("%s: \"%s\"", h$name, h$value));
		}
	}

event mime_segment_data(c: connection, length: count, data: string)
 	{
	if ( c$id$resp_p != 110/tcp )
		return;
	
	local session = get_mime_session(c, T);

 	if ( session$data_offset < 256 )
 		mime_log_msg(session, "data", fmt("%d: %s", length, data));

 	session$data_offset = session$data_offset + length;
 	}

event mime_event(c: connection, event_type: string, detail: string)
	{
	if ( c$id$resp_p != 110/tcp )
		return;
	
	local session = get_mime_session(c, T);
	mime_log_msg(session, "event", fmt("%s: %s", event_type, detail));
	}
