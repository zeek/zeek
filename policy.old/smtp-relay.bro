# $Id: smtp-relay.bro 5911 2008-07-03 22:59:01Z vern $
#
# Tracks email relaying.

@load smtp
@load mime

module SMTP;

redef process_smtp_relay = T;

export {
	const relay_log = open_log_file("relay") &redef;
}

global print_smtp_relay: function(t: table[count] of smtp_session_info,
					idx: count): interval;

global smtp_relay_table: table[count] of smtp_session_info
	&write_expire = 5 min &expire_func = print_smtp_relay;

global smtp_session_by_recipient: table[string] of smtp_session_info
	&write_expire = 5 min;
global smtp_session_by_message_id: table[string] of smtp_session_info
	&write_expire = 5 min;
global smtp_session_by_content_hash: table[string] of smtp_session_info
	&write_expire = 5 min;


function add_to_smtp_relay_table(session: smtp_session_info)
	{
	if ( session$id !in smtp_relay_table )
		smtp_relay_table[session$id] = session;
	}

function check_relay_1(session: smtp_session_info, rcpt: string)
	{
	if ( session$external_orig && rcpt != local_mail_addr )
		{
		smtp_message(session,
			fmt("relaying(1) message (from %s, to %s) to address %s",
				session$connection_id$orig_h,
				session$connection_id$resp_h,
				rcpt));

		if ( session$relay_1_rcpt != "" )
			session$relay_1_rcpt = cat(session$relay_1_rcpt, ",");

		session$relay_1_rcpt = cat(session$relay_1_rcpt, rcpt);
		add_to_smtp_relay_table(session);
		}
	}

function check_relay_2(session: smtp_session_info, rcpt: string)
	{
	if ( rcpt in smtp_session_by_recipient )
		{
		local prev_session = smtp_session_by_recipient[rcpt];

		# Should only check the first condition only (external
		# followed by internal) but let's include the second one
		# for testing purposes for now.
		if ( (prev_session$external_orig && ! session$external_orig) ||
		     (! prev_session$external_orig && session$external_orig) )
			{
			smtp_message(session,
				fmt("relaying(2) message (seen during #%d) to address %s (%s -> %s, %s -> %s)",
					prev_session$id, rcpt,
					prev_session$connection_id$orig_h,
					prev_session$connection_id$resp_h,
					session$connection_id$orig_h,
					session$connection_id$resp_h));

			session$relay_2_from = prev_session$id;
			++prev_session$relay_2_to;

			add_to_smtp_relay_table(session);
			add_to_smtp_relay_table(prev_session);
			}
		}

	smtp_session_by_recipient[rcpt] = session;
	}

function check_relay_3(session: MIME::mime_session_info, msg_id: string)
	{
	local smtp_session = session$smtp_session;

	if ( msg_id in smtp_session_by_message_id )
		{
		local prev_smtp_session = smtp_session_by_message_id[msg_id];

		smtp_message(smtp_session,
			fmt("relaying(3) message (seen during #%d) with id %s (%s -> %s, %s -> %s)",
				prev_smtp_session$id, msg_id,
				prev_smtp_session$connection_id$orig_h,
				prev_smtp_session$connection_id$resp_h,
				smtp_session$connection_id$orig_h,
				smtp_session$connection_id$resp_h));

		smtp_session$relay_3_from = prev_smtp_session$id;
		++prev_smtp_session$relay_3_to;

		add_to_smtp_relay_table(smtp_session);
		add_to_smtp_relay_table(prev_smtp_session);
		}
	else
		smtp_session_by_message_id[msg_id] = smtp_session;
	}

function check_relay_4(session: MIME::mime_session_info, content_hash: string)
	{
	local smtp_session = session$smtp_session;
	smtp_session$content_hash = content_hash;

	if ( content_hash in smtp_session_by_content_hash )
		{
		local prev_smtp_session = smtp_session_by_content_hash[content_hash];
		smtp_message(smtp_session,
			fmt("relaying(4) message (seen during #%d) with hash %s (%s -> %s, %s -> %s)",
				prev_smtp_session$id,
				string_to_ascii_hex(content_hash),
				prev_smtp_session$connection_id$orig_h,
				prev_smtp_session$connection_id$resp_h,
				smtp_session$connection_id$orig_h,
				smtp_session$connection_id$resp_h));

		smtp_session$relay_4_from = prev_smtp_session$id;
		++prev_smtp_session$relay_4_to;

		add_to_smtp_relay_table(smtp_session);
		add_to_smtp_relay_table(prev_smtp_session);
		}
	else
		smtp_session_by_content_hash[content_hash] = smtp_session;
	}

# event mime_all_data(c: connection, length: count, data: string)
#  	{
#  	local session = get_mime_session(c, T);
#  	session$content_hash = md5_hash(data);
# 	if ( process_smtp_relay )
# 	 	check_relay_4(session, session$content_hash);
#  	# mime_log_msg(session, "all data", fmt("%s", data));
#  	}

event mime_content_hash(c: connection, content_len: count, hash_value: string)
	{
	local session = MIME::get_session(c, T);
	session$content_hash = hash_value;
	if ( process_smtp_relay && content_len > 0 )
		check_relay_4(session, session$content_hash);
	}

function relay_flow(from: count, to: count): string
	{
	if ( from > 0 )
		return fmt("<#%d", from);

	if ( to > 0 )
		return fmt(">%d", to);

	return "-";
	}

function print_smtp_relay(t: table[count] of smtp_session_info,
				idx: count): interval
	{
	local session = t[idx];

	print relay_log, fmt("#%d: %s",
		session$id,
		directed_id_string(session$connection_id, T));

	print relay_log, fmt("#%d: RCPT: <%s>, Subject: %s",
		session$id,
		session$recipients, session$subject);

	print relay_log, fmt("#%d: detected: [%s %s %s %s] %s",
		session$id,
		session$relay_1_rcpt == "" ? "-" : "1",
		relay_flow(session$relay_2_from, session$relay_2_to),
		relay_flow(session$relay_3_from, session$relay_3_to),
		relay_flow(session$relay_4_from, session$relay_4_to),
		session$content_gap ? "(content gap)" : "");

	print relay_log, fmt("#%d: relay 1: <%s>",
		session$id,
		session$relay_1_rcpt);

	return 0 sec;
	}
