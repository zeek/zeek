# $Id: pop3.bro 4758 2007-08-10 06:49:23Z vern $
#
# Analyzer for Post Office Protocol, version 3.
#
# If you want to decode the mail itself, also load mime-pop.bro.

@load login

module POP3;

export {
	# Report if source triggers more ERR messages.
	const error_threshold: count = 3 &redef;
 	# Don't log these commands.
	const ignore_commands: set[string] = { "STAT" } &redef;
}

redef capture_filters += { ["pop3"] = "port 110" };

global pop3_ports = { 110/tcp } &redef;
redef dpd_config += { [ANALYZER_POP3] = [$ports = pop3_ports] };

const log_file = open_log_file("pop3") &redef;

type pop3_session_info: record {
	id: count; 		# Unique session ID.
	quit_sent: bool;	# Client issued a QUIT.
	last_command: string;	# Last command of client.
};


global pop_log: function(conn: pop3_session_info,
				command: string, message: string);
global get_connection: function(id: conn_id): pop3_session_info;


global pop_connections:
	table[conn_id] of pop3_session_info &read_expire = 60 mins;
global pop_connection_weirds:
	table[addr] of count &default=0 &read_expire = 60 mins;
global pop_session_id = 0;


event pop3_request(c: connection, is_orig: bool, command: string, arg: string)
	{
	local conn = get_connection(c$id);

	pop_log(conn, command, fmt("%.6f #%s > %s %s",
		network_time(), prefixed_id(conn$id), command, arg));

	conn$last_command = command;

	if ( command == "QUIT" )
		conn$quit_sent = T;
	}

event pop3_reply(c: connection, is_orig: bool, cmd: string, msg: string)
	{
	local conn = get_connection(c$id);

	pop_log(conn, cmd,
		fmt("%.6f #%s < %s %s", network_time(), prefixed_id(conn$id), cmd, msg));

	if ( cmd == "OK" )
		{
		if ( conn$quit_sent )
			delete pop_connections[c$id];
		}

	else if ( cmd == "ERR" )
		{
		++pop_connection_weirds[c$id$orig_h];
		if ( pop_connection_weirds[c$id$orig_h] > error_threshold )
			print log_file, fmt("%.6f #%s %s/%d > %s/%d WARNING: error count exceeds threshold",
					network_time(), prefixed_id(conn$id),
					c$id$orig_h, c$id$orig_p,
					c$id$resp_h, c$id$resp_p);
		}
	}

event pop3_login_success(c: connection, is_orig: bool,
				user: string, password: string)
	{
	local conn = get_connection(c$id);

	local pw = byte_len(password) != 0 ? password : "<not seen>";

	print log_file, fmt("%.6f #%s > login successful: user %s password: %s",
				network_time(), prefixed_id(conn$id), user, pw);

	event login_success(c, user, "", password, "");
	}

event pop3_login_failure(c: connection, is_orig: bool,
				user: string, password: string)
	{
	local conn = get_connection(c$id);

	print log_file, fmt("%.6f #%s > login failed: user %s password: %s",
			network_time(), prefixed_id(conn$id), user, password);

	event login_failure(c, user, "", password, "");
	}

# event pop3_data(c: connection, is_orig: bool, data: string)
# 	{
# 	# We could instantiate partial connections here if we wished,
# 	# but at considerable cost in terms of event counts.
# 	local conn = get_connection(c$id);
# 	}

event pop3_unexpected(c: connection, is_orig: bool, msg: string, detail: string)
	{
	local conn = get_connection(c$id);
	print log_file, fmt("%.6f #%s unexpected cmd: %s detail: %s",
				network_time(), prefixed_id(conn$id),
				msg, detail);
	}

event pop3_terminate(c: connection, is_orig: bool, msg: string)
	{
	delete pop_connections[c$id];
	}


function pop_log(conn: pop3_session_info, command: string, message: string)
	{
	if ( command !in ignore_commands )
		{
		if ( (command == "OK" || command == "ERR") &&
		     conn$last_command in ignore_commands )
			;
		else
			print log_file, message;
		}
	}

function get_connection(id: conn_id): pop3_session_info
	{
	if ( id in pop_connections )
		return pop_connections[id];

	local conn: pop3_session_info;

	conn$id = ++pop_session_id;
	conn$quit_sent = F;
	conn$last_command = "INIT";
	pop_connections[id] = conn;

	print log_file, fmt("%.6f #%s %s/%d > %s/%d: new connection",
				network_time(), prefixed_id(conn$id),
				id$orig_h, id$orig_p, id$resp_h, id$resp_p);

	return conn;
	}
