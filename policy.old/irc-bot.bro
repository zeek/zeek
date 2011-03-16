# $Id:$

@load conn
@load notice
@load weird

module IrcBot;

export {
	global detailed_log = open_log_file("irc.detailed") &redef;
	global bot_log = open_log_file("irc-bots") &redef;

	global summary_interval = 1 min &redef;

	global detailed_logging = T &redef;
	global content_dir = "irc-bots" &redef;

	global bot_nicks =
		  /^\[([^\]]+\|)+[0-9]{2,}]/		# [DEU|XP|L|00]
		| /^\[[^ ]+\]([^ ]+\|)+([0-9a-zA-Z-]+)/	# [0]CHN|3436036 [DEU][1]3G-QE
		| /^DCOM[0-9]+$/			# DCOM7845
		| /^\{[A-Z]+\}-[0-9]+/			# {XP}-5021040
		| /^\[[0-9]+-[A-Z0-9]+\][a-z]+/		# [0058-X2]wpbnlgwf
		| /^\[[a-zA-Z0-9]\]-[a-zA-Z0-9]+$/	# [SD]-743056826
		| /^[a-z]+[A-Z]+-[0-9]{5,}$/
		| /^[A-Z]{3}-[0-9]{4}/			# ITD-1119
	;

	global bot_cmds =
		  /(^| *)[.?#!][^ ]{0,5}(scan|ndcass|download|cvar\.|execute|update|dcom|asc|scanall) /
		| /(^| +\]\[ +)\* (ipscan|wormride)/
		| /(^| *)asn1/
	;

	global skip_msgs =
		  /.*AUTH .*/
		| /.*\*\*\* Your host is .*/
		| /.*\*\*\* If you are having problems connecting .*/
	;

	redef enum Notice += {
		IrcBotServerFound,
		IrcBotClientFound,
	};

	type channel: record {
		name: string;
		passwords: set[string];
		topic: string &default="";
		topic_history: vector of string;
	};

	type bot_client: record {
		host: addr;
		p: port;
		nick: string &default="";
		user: string &default="";
		realname: string &default="";
		channels: table[string] of channel;
		servers: set[addr] &optional;
		first_seen: time;
		last_seen: time;
	};

	type bot_server: record {
		host: addr;
		p: set[port];
		clients: table[addr] of bot_client;
		global_users: string &default="";
		passwords: set[string];
		channels: table[string] of channel;
		first_seen: time;
		last_seen: time;
	};

	type bot_conn: record {
		client: bot_client;
		server: bot_server;
		conn: connection;
		fd: file;
		ircx: bool &default=F;
	};

	# We keep three sets of clients/servers:
	#  (1) tables containing all IRC clients/servers
	#  (2) sets containing potential bot hosts
	#  (3) sets containing confirmend bot hosts
	#
	# Hosts are confirmed when a connection is established between
	# potential bot hosts.
	#
	# FIXME: (1) should really be moved into the general IRC script.

	global expire_server:
		function(t: table[addr] of bot_server, idx: addr): interval;
	global expire_client:
		function(t: table[addr] of bot_client, idx: addr): interval;

	global servers: table[addr] of bot_server &write_expire=24 hrs
			&expire_func=expire_server &persistent;
	global clients: table[addr] of bot_client &write_expire=24 hrs
			&expire_func=expire_client &persistent;

	global potential_bot_clients: set[addr] &persistent;
	global potential_bot_servers: set[addr] &persistent;
	global confirmed_bot_clients: set[addr] &persistent;
	global confirmed_bot_servers: set[addr] &persistent;

	# All IRC connections.
	global conns: table[conn_id] of bot_conn &persistent;

	# Connections between confirmed hosts.
	global bot_conns: set[conn_id] &persistent;

	# Helper functions for readable output.
	global strset_to_str: function(s: set[string]) : string;
	global portset_to_str: function(s: set[port]) : string;
	global addrset_to_str: function(s: set[addr]) : string;
}

function strset_to_str(s: set[string]) : string
	{
	if ( |s| == 0 )
		return "<none>";

	local r = "";
	for ( i in s )
		{
		if ( r != "" )
			r = cat(r, ",");
		r = cat(r, fmt("\"%s\"", i));
		}

	return r;
	}

function portset_to_str(s: set[port]) : string
	{
	if ( |s| == 0 )
		return "<none>";

	local r = "";
	for ( i in s )
		{
		if ( r != "" )
			r = cat(r, ",");
		r = cat(r, fmt("%d", i));
		}

	return r;
	}

function addrset_to_str(s: set[addr]) : string
	{
	if ( |s| == 0 )
		return "<none>";

	local r = "";
	for ( i in s )
		{
		if ( r != "" )
			r = cat(r, ",");
		r = cat(r, fmt("%s", i));
		}

	return r;
	}

function fmt_time(t: time) : string
	{
	return strftime("%y-%m-%d-%H-%M-%S", t);
	}

event print_bot_state()
	{
	local bot_summary_log = open_log_file("irc-bots.summary");
	disable_print_hook(bot_summary_log);

	print bot_summary_log, "---------------------------";
	print bot_summary_log, strftime("%y-%m-%d-%H-%M-%S", network_time());
	print bot_summary_log, "---------------------------";
	print bot_summary_log;
	print bot_summary_log, "Known servers";

	for ( h in confirmed_bot_servers )
		{
		local s = servers[h];

		print bot_summary_log,
			fmt("    %s %s - clients: %d ports %s password(s) %s last-seen %s first-seen %s global-users %s",
				(is_local_addr(s$host) ? "L" : "R"),
				s$host, length(s$clients), portset_to_str(s$p),
				strset_to_str(s$passwords),
				fmt_time(s$last_seen), fmt_time(s$first_seen),
				s$global_users);

		for ( name in s$channels )
			{
			local ch = s$channels[name];
			print bot_summary_log,
				fmt("        channel %s: topic \"%s\", password(s) %s",
					ch$name, ch$topic,
					strset_to_str(ch$passwords));
			}
		}

	print bot_summary_log, "\nKnown clients";

	for ( h in confirmed_bot_clients )
		{
		local c = clients[h];
		print bot_summary_log,
			fmt("    %s %s - server(s) %s user %s nick %s realname %s last-seen %s first-seen %s",
				(is_local_addr(h) ? "L" : "R"), h,
				addrset_to_str(c$servers),
				c$user, c$nick, c$realname,
				fmt_time(c$last_seen), fmt_time(c$first_seen));
		}

	close(bot_summary_log);

	if ( summary_interval != 0 secs )
		schedule summary_interval { print_bot_state() };
	}

event bro_init()
	{
	if ( summary_interval != 0 secs )
		schedule summary_interval { print_bot_state() };
	}

function do_log_force(c: connection, msg: string)
	{
	local id = c$id;
	print bot_log, fmt("%.6f %s:%d > %s:%d %s %s",
				network_time(), id$orig_h, id$orig_p,
				id$resp_h, id$resp_p, c$addl, msg);
	}

function do_log(c: connection, msg: string)
	{
	if ( c$id !in bot_conns )
		return;

	do_log_force(c, msg);
	}

function log_msg(c: connection, cmd: string, prefix: string, msg: string)
	{
	if ( skip_msgs in msg )
		return;

	do_log(c, fmt("MSG command=%s prefix=%s msg=\"%s\"", cmd, prefix, msg));
	}

function update_timestamps(c: connection) : bot_conn
	{
	local conn = conns[c$id];

	conn$client$last_seen = network_time();
	conn$server$last_seen = network_time();

	# To prevent the set of entries from premature expiration,
	# we need to make a write access (can't use read_expire as we
	# iterate over the entries on a regular basis).
	clients[c$id$orig_h] = conn$client;
	servers[c$id$resp_h] = conn$server;

	return conn;
	}

function add_server(c: connection) : bot_server
	{
	local s_h = c$id$resp_h;

	if ( s_h in servers )
		return servers[s_h];

	local empty_table1: table[addr] of bot_client;
	local empty_table2: table[string] of channel;
	local empty_set: set[string];
	local empty_set2: set[port];

	local server = [$host=s_h, $p=empty_set2, $clients=empty_table1,
			$channels=empty_table2, $passwords=empty_set,
			$first_seen=network_time(), $last_seen=network_time()];
	servers[s_h] = server;

	return server;
	}

function add_client(c: connection) : bot_client
	{
	local c_h = c$id$orig_h;

	if ( c_h in clients )
		return clients[c_h];

	local empty_table: table[string] of channel;
	local empty_set: set[addr];
	local client = [$host=c_h, $p=c$id$resp_p, $servers=empty_set,
			$channels=empty_table, $first_seen=network_time(),
			$last_seen=network_time()];
	clients[c_h] = client;

	return client;
	}

function check_bot_conn(c: connection)
	{
	if ( c$id in bot_conns )
		return;

	local client = c$id$orig_h;
	local server = c$id$resp_h;

	if ( client !in potential_bot_clients || server !in potential_bot_servers )
		return;

	# New confirmed bot_conn.

	add bot_conns[c$id];

	if ( server !in confirmed_bot_servers )
		{
		NOTICE([$note=IrcBotServerFound, $src=server, $p=c$id$resp_p, $conn=c,
				$msg=fmt("ircbot server found: %s:%d", server, $p=c$id$resp_p)]);
		add confirmed_bot_servers[server];
		}

	if ( client !in confirmed_bot_clients )
		{
		NOTICE([$note=IrcBotClientFound, $src=client, $p=c$id$orig_p, $conn=c,
				$msg=fmt("ircbot client found: %s:%d", client, $p=c$id$orig_p)]);
		add confirmed_bot_clients[client];
		}
	}

function get_conn(c: connection) : bot_conn
	{
	local conn: bot_conn;

	if ( c$id in conns )
		{
		check_bot_conn(c);
		return update_timestamps(c);
		}

	local c_h = c$id$orig_h;
	local s_h = c$id$resp_h;

	local client : bot_client;
	local server : bot_server;

	if ( c_h in clients )
		client = clients[c_h];
	else
		client = add_client(c);

	if ( s_h in servers )
		server = servers[s_h];
	else
		server = add_server(c);

	server$clients[c_h] = client;
	add server$p[c$id$resp_p];
	add client$servers[s_h];

	conn$server = server;
	conn$client = client;
	conn$conn = c;
	conns[c$id] = conn;
	update_timestamps(c);

	return conn;
	}

function expire_server(t: table[addr] of bot_server, idx: addr): interval
	{
	local server = t[idx];
	for ( c in server$clients )
		{
		local client = server$clients[c];
		delete client$servers[idx];
		}

	delete potential_bot_servers[idx];
	delete confirmed_bot_servers[idx];
	return 0secs;
	}

function expire_client(t: table[addr] of bot_client, idx: addr): interval
	{
	local client = t[idx];
	for ( s in client$servers )
		if ( s in servers )
			delete servers[s]$clients[idx];
	delete potential_bot_clients[idx];
	delete confirmed_bot_clients[idx];
	return 0secs;
	}

function remove_connection(c: connection)
	{
	local conn = conns[c$id];
	delete conns[c$id];
	delete bot_conns[c$id];
	}

event connection_state_remove(c: connection)
	{
	if ( c$id !in conns )
		return;

	remove_connection(c);
	}

event bro_init()
	{
	set_buf(detailed_log, F);
	set_buf(bot_log, F);
	}

event irc_client(c: connection, prefix: string, data: string)
	{
	if ( detailed_logging )
		print detailed_log, fmt("%.6f %s > (%s) %s", network_time(), id_string(c$id), prefix, data);

	local conn = get_conn(c);

	if ( data == /^ *[iI][rR][cC][xX] *$/ )
		conn$ircx = T;
	}

event irc_server(c: connection, prefix: string, data: string)
	{
	if ( detailed_logging )
		print detailed_log, fmt("%.6f %s < (%s) %s", network_time(), id_string(c$id), prefix, data);

	local conn = get_conn(c);
	}

event irc_user_message(c: connection, user: string, host: string, server: string, real_name: string)
	{
	local conn = get_conn(c);
	conn$client$user = user;
	conn$client$realname = real_name;

	do_log(c, fmt("USER user=%s host=%s server=%s real_name=%s", user, host, server, real_name));
	}

function get_channel(conn: bot_conn, channel: string) : channel
	{
	if ( channel in conn$server$channels )
		return conn$server$channels[channel];
	else
		{
		local empty_set: set[string];
		local empty_vec: vector of string;
		local ch = [$name=channel, $passwords=empty_set, $topic_history=empty_vec];
		conn$server$channels[ch$name] = ch;
		return ch;
		}
	}

event irc_join_message(c: connection, info_list: irc_join_list)
	{
	local conn = get_conn(c);

	for ( i in info_list )
		{
		local ch = get_channel(conn, i$channel);

		if ( i$password != "" )
			add ch$passwords[i$password];

		conn$client$channels[ch$name] = ch;

		do_log(c, fmt("JOIN channel=%s password=%s", i$channel, i$password));
		}
	}

global urls: set[string] &read_expire = 7 days &persistent;

event http_request(c: connection, method: string, original_URI: string,
			unescaped_URI: string, version: string)
	{
	if ( original_URI in urls )
		do_log_force(c, fmt("Request for URL %s", original_URI));
	}

event irc_channel_topic(c: connection, channel: string, topic: string)
	{
	if ( bot_cmds in topic )
		{
		do_log_force(c, fmt("Matching TOPIC %s", topic));
		add potential_bot_servers[c$id$resp_h];
		}

	local conn = get_conn(c);

	local ch = get_channel(conn, channel);
	ch$topic_history[|ch$topic_history| + 1] = ch$topic;
	ch$topic = topic;

	if ( c$id in bot_conns )
		{
		do_log(c, fmt("TOPIC channel=%s topic=\"%s\"", channel, topic));

		local s = split(topic, / /);
		for ( i in s )
			{
			local w = s[i];
			if ( w == /[a-zA-Z]+:\/\/.*/ )
				{
				add urls[w];
				do_log(c, fmt("URL channel=%s url=\"%s\"",
						channel, w));
				}
			}
		}
	}

event irc_nick_message(c: connection, who: string, newnick: string)
	{
	if ( bot_nicks in newnick )
		{
		do_log_force(c, fmt("Matching NICK %s", newnick));
		add potential_bot_clients[c$id$orig_h];
		}

	local conn = get_conn(c);
	conn$client$nick = newnick;

	do_log(c, fmt("NICK who=%s nick=%s", who, newnick));
	}

event irc_password_message(c: connection, password: string)
	{
	local conn = get_conn(c);
	add conn$server$passwords[password];

	do_log(c, fmt("PASS password=%s", password));
	}

event irc_privmsg_message(c: connection, source: string, target: string,
				message: string)
	{
	log_msg(c, "privmsg", source, fmt("->%s %s", target, message));
	}

event irc_notice_message(c: connection, source: string, target: string,
				message: string)
	{
	log_msg(c, "notice", source, fmt("->%s %s", target, message));
	}

event irc_global_users(c: connection, prefix: string, msg: string)
	{
	local conn = get_conn(c);

	# Better would be to parse the message to extract the counts.
	conn$server$global_users = msg;

	log_msg(c, "globalusers", prefix, msg);
	}
