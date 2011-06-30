# $Id: irc.bro 4758 2007-08-10 06:49:23Z vern $

@load conn-id
@load notice
@load weird

@load signatures

module IRC;

export {
	const log_file = open_log_file("irc") &redef;

	type irc_user: record {
		u_nick: string;		# nick name
		u_real: string;		# real name
		u_host: string;		# client host
		u_channels: set[string];	# channels the user is member of
		u_is_operator: bool;	# user is server operator
		u_conn: connection;	# connection handle
	};

	type irc_channel: record {
		c_name: string;		# channel name
		c_users: set[string];	# users in channel
		c_ops: set[string];	# channel operators
		c_type: string;		# channel type
		c_modes: string;	# channel modes
		c_topic: string;	# channel topic
	};

	global expired_user:
		function(t: table[string] of irc_user, idx: string): interval;
	global expired_channel:
		function(t: table[string] of irc_channel, idx: string): interval;

	# Commands to ignore in irc_request/irc_message.
	const ignore_in_other_msgs = { "PING", "PONG", "ISON" } &redef;

	# Return codes to ignore in irc_response
	const ignore_in_other_responses: set[count] = {
		303 # RPL_ISON
	} &redef;

	# Active users, indexed by nick.
	global active_users: table[string] of irc_user &read_expire = 6 hrs
		&expire_func = expired_user &redef;

	# Active channels, indexed by channel name.
	global active_channels: table[string] of irc_channel
					&read_expire = 6 hrs
					&expire_func = expired_channel &redef;

	# Strings that generate a notice if found in session dialog.
	const hot_words =
		  /.*etc\/shadow.*/
		| /.*etc\/ldap.secret.*/
		| /.*phatbot.*/
		| /.*botnet.*/
	&redef;

	redef enum Notice += {
		IRC_HotWord,
	};
}


# IRC ports.  This could be widened to 6660-6669, say.
redef capture_filters += { ["irc-6666"] = "port 6666" };
redef capture_filters += { ["irc-6667"] = "port 6667" };

# DPM configuration.
global irc_ports = { 6666/tcp, 6667/tcp } &redef;
redef dpd_config += { [ANALYZER_IRC] = [$ports = irc_ports] };

redef Weird::weird_action += {
	["irc_invalid_dcc_message_format"]	= Weird::WEIRD_FILE,
	["irc_invalid_invite_message_format"]	= Weird::WEIRD_FILE,
	["irc_invalid_kick_message_format"]	= Weird::WEIRD_FILE,
	["irc_invalid_line"]	= Weird::WEIRD_FILE,
	["irc_invalid_mode_message_format"]	= Weird::WEIRD_FILE,
	["irc_invalid_names_line"]	= Weird::WEIRD_FILE,
	["irc_invalid_njoin_line"]	= Weird::WEIRD_FILE,
	["irc_invalid_notice_message_format"]	= Weird::WEIRD_FILE,
	["irc_invalid_oper_message_format"]	= Weird::WEIRD_FILE,
	["irc_invalid_privmsg_message_format"]	= Weird::WEIRD_FILE,
	["irc_invalid_reply_number"]	= Weird::WEIRD_FILE,
	["irc_invalid_squery_message_format"]	= Weird::WEIRD_FILE,
	["irc_invalid_who_line"]	= Weird::WEIRD_FILE,
	["irc_invalid_who_message_format"]	= Weird::WEIRD_FILE,
	["irc_invalid_whois_channel_line"]	= Weird::WEIRD_FILE,
	["irc_invalid_whois_message_format"]	= Weird::WEIRD_FILE,
	["irc_invalid_whois_operator_line"]	= Weird::WEIRD_FILE,
	["irc_invalid_whois_user_line"]	= Weird::WEIRD_FILE,
	["irc_line_size_exceeded"]	= Weird::WEIRD_FILE,
	["irc_line_too_short"]	= Weird::WEIRD_FILE,
	["irc_partial_request"]	= Weird::WEIRD_FILE,
	["irc_too_many_invalid"]	= Weird::WEIRD_FILE,
};

# # IRC servers to identify server-to-server connections.
# redef irc_servers = {
# 	# German IRCnet servers
# 	irc.leo.org,
# 	irc.fu-berlin.de,
# 	irc.uni-erlangen.de,
# 	irc.belwue.de,
# 	irc.freenet.de,
# 	irc.tu-ilmenau.de,
# 	irc.rz.uni-karlsruhe.de,
# };

global conn_list: table[conn_id] of count;
global conn_ID = 0;
global check_connection: function(c: connection);

function irc_check_hot(c: connection, s: string, context: string)
	{
	if ( s == hot_words )
		NOTICE([$note=IRC_HotWord, $conn=c,
			$msg=fmt("IRC hot word in: %s", context)]);
	}

function log_activity(c: connection, msg: string)
	{
	print log_file, fmt("%.6f #%s %s",
				network_time(), conn_list[c$id], msg);
	}

event connection_state_remove(c: connection)
	{
	delete conn_list[c$id];
	}

event irc_request(c: connection, prefix: string,
			command: string, arguments: string)
	{
	check_connection(c);

	local context = fmt("%s %s", command, arguments);
	irc_check_hot(c, command, context);
	irc_check_hot(c, arguments, context);

	if ( command !in ignore_in_other_msgs )
		log_activity(c, fmt("other request%s%s: %s",
					prefix == "" ? "" : " ",
					prefix, context));
	}

event irc_reply(c: connection, prefix: string, code: count, params: string)
	{
	check_connection(c);

	local context = fmt("%s %s", code, params);
	irc_check_hot(c, params, context);

	if ( code !in ignore_in_other_responses )
		log_activity(c, fmt("other response from %s: %s",
					prefix, context));
	}

event irc_message(c: connection, prefix: string,
			command: string, message: string)
	{
	check_connection(c);

	# Sanity checks whether this is indeed IRC.
	#
	# If we happen to parse an HTTP connection, the server "commands" will
	# end with ":".
	if ( command == /.*:$/ )
		{
		local aid = current_analyzer();
		event protocol_violation(c, ANALYZER_IRC, aid, "broken server response");
		return;
		}

	local context = fmt("%s %s", command, message);
	irc_check_hot(c, command, context);
	irc_check_hot(c, message, context);

	if ( command !in ignore_in_other_msgs )
		log_activity(c, fmt("other server message from %s: %s",
					prefix, context));
	}

event irc_user_message(c: connection, user: string, host: string,
			server: string, real_name: string)
	{
	check_connection(c);

	log_activity(c, fmt("new user, user='%s', host='%s', server='%s', real = '%s'",
				user, host, server, real_name));

	if ( user in active_users )
		active_users[user]$u_conn = c;
	else
		{
		local u: irc_user;
		u$u_nick = user;
		u$u_real = real_name;
		u$u_conn = c;
		u$u_host = "";
		u$u_is_operator = F;
		active_users[user] = u;
		}
	}

event irc_quit_message(c: connection, nick: string, message: string)
	{
	check_connection(c);

	log_activity(c, fmt("user '%s' leaving%s", nick,
				message == "" ? "" : fmt(", \"%s\"", message)));

	# Remove from lists.
	if ( nick in active_users )
		{
		delete active_users[nick];
		for ( my_channel in active_channels )
			delete active_channels[my_channel]$c_users[nick];
		}
	}

function check_message(c: connection, source: string, target: string,
			msg: string, msg_type: string)
	{
	check_connection(c);
	irc_check_hot(c, msg, msg);
	log_activity(c, fmt("%s%s to '%s': %s", msg_type,
				source != "" ? fmt(" from '%s'", source) : "",
				target, msg));
	}

event irc_privmsg_message(c: connection, source: string, target: string,
				message: string)
	{
	check_message(c, source, target, message, "message");
	}

event irc_notice_message(c: connection, source: string, target: string,
				message: string)
	{
	check_message(c, source, target, message, "notice");
	}

event irc_squery_message(c: connection, source: string, target: string,
				message: string)
	{
	check_message(c, source, target, message, "squery");
	}

event irc_join_message(c: connection, info_list: irc_join_list)
	{
	check_connection(c);

	for ( l in info_list )
		{
		log_activity(c, fmt("user '%s' joined '%s'%s",
					l$nick, l$channel,
					l$password != "" ?
						fmt("with password '%s'",
							l$password) : ""));

		if ( l$nick == "" )
			next;

		if ( l$nick in active_users )
			add (active_users[l$nick]$u_channels)[l$channel];
		else
			{
			local user: irc_user;
			user$u_nick = l$nick;
			user$u_real = "";
			user$u_conn = c;
			user$u_host = "";
			user$u_is_operator = F;
			add user$u_channels[l$channel];

			active_users[l$nick] = user;
			}

		# Add channel to lists.
		if ( l$channel in active_channels )
			add (active_channels[l$channel]$c_users)[l$nick];
		else
			{
			local my_c: irc_channel;
			my_c$c_name = l$channel;
			add my_c$c_users[l$nick];

			my_c$c_type = my_c$c_modes = "";

			active_channels[l$channel] = my_c;
			}
		}
	}

event irc_part_message(c: connection, nick: string,
			chans: string_set, message: string)
	{
	check_connection(c);

	local channel_str = "";
	for ( ch in chans )
		channel_str = channel_str == "" ?
			ch : fmt("%s, %s", channel_str, ch);

	log_activity(c, fmt("%s channel '%s'%s",
				nick == "" ? "leaving" :
					fmt("user '%s' leaving", nick),
				channel_str,
				message == "" ?
					"" : fmt("with message '%s'", message)));

	# Remove user from channel.
	if ( nick == "" )
		return;

	for ( ch in active_channels )
		{
		delete (active_channels[ch]$c_users)[nick];
		delete (active_channels[ch]$c_ops)[nick];
		if ( nick in active_users )
			delete (active_users[nick]$u_channels)[ch];
		}
	}

event irc_nick_message(c: connection, who: string, newnick: string)
	{
	check_connection(c);

	log_activity(c, fmt("%s nick name to '%s'",
				who == "" ?  "changing" :
						fmt("user '%s' changing", who),
				newnick));
	}

event irc_invalid_nick(c: connection)
	{
	check_connection(c);
	log_activity(c, "changing nick name failed");
	}

event irc_network_info(c: connection, users: count, services: count,
			servers: count)
	{
	check_connection(c);
	log_activity(c, fmt("network includes %d users, %d services, %d servers",
				users, services, servers));
	}

event irc_server_info(c: connection, users: count, services: count,
			servers: count)
	{
	check_connection(c);
	log_activity(c, fmt("server includes %d users, %d services, %d peers",
				users, services, servers));
	}

event irc_channel_info(c: connection, chans: count)
	{
	check_connection(c);
	log_activity(c, fmt("network includes %d channels", chans));
	}

event irc_who_line(c: connection, target_nick: string, channel: string,
			user: string, host: string, server: string,
			nick: string, params: string, hops: count,
			real_name: string)
	{
	check_connection(c);

	log_activity(c, fmt("channel '%s' includes '%s' on %s connected to %s with nick '%s', real name '%s', params %s",
				channel, user, host, server,
				nick, real_name, params));

	if ( nick == "" || channel == "" )
		return;

	if ( nick in active_users )
		active_users[nick]$u_conn = c;

	else
		{
		local myuser: irc_user;
		myuser$u_nick = nick;
		myuser$u_real = real_name;
		myuser$u_conn = c;
		myuser$u_host = host;
		myuser$u_is_operator = F;
		add myuser$u_channels[channel];

		active_users[nick] = myuser;

		if ( channel in active_channels )
			add (active_channels[channel]$c_users)[nick];
		else
			{
			local my_c: irc_channel;
			my_c$c_name = channel;
			add my_c$c_users[nick];
			my_c$c_type = "";
			my_c$c_modes = "";

			active_channels[channel] = my_c;
			}
		}
	}

event irc_who_message(c: connection, mask: string, oper: bool)
	{
	check_connection(c);

	log_activity(c, fmt("WHO with mask %s%s", mask,
				oper ? ", only operators" : ""));
	}

event irc_whois_message(c: connection, server: string, users: string)
	{
	check_connection(c);

	log_activity(c, fmt("WHOIS%s for user(s) %s",
				server == "" ?
					server : fmt(" to server %s", server),
				users));
	}

event irc_whois_user_line(c: connection, nick: string,
				user: string, host: string, real_name: string)
	{
	check_connection(c);

	log_activity(c, fmt("user '%s' with nick '%s' on host %s has real name '%s'",
				user, nick, host, real_name));

	if ( nick in active_users )
		{
		active_users[nick]$u_real = real_name;
		active_users[nick]$u_host = host;
		}
	else
		{
		local u: irc_user;
		u$u_nick = nick;
		u$u_real = real_name;
		u$u_conn = c;
		u$u_host = host;
		u$u_is_operator = F;

		active_users[nick] = u;
		}
	}

event irc_whois_operator_line(c: connection, nick: string)
	{
	check_connection(c);
	log_activity(c, fmt("user '%s' is an IRC operator", nick));

	if ( nick in active_users )
		active_users[nick]$u_is_operator = T;
	else
		{
		local u: irc_user;
		u$u_nick = nick;
		u$u_real = "";
		u$u_conn = c;
		u$u_host = "";
		u$u_is_operator = T;

		active_users[nick] = u;
		}
	}

event irc_whois_channel_line(c: connection, nick: string, chans: string_set)
	{
	check_connection(c);

	local message = fmt("user '%s' is on channels:", nick);
	for ( channel in chans )
		message = fmt("%s %s", message, channel);

	log_activity(c, message);

	if ( nick in active_users )
		{
		for ( ch in chans )
			add active_users[nick]$u_channels[ch];
		}
	else
		{
		local u: irc_user;
		u$u_nick = nick;
		u$u_real = "";
		u$u_conn = c;
		u$u_host = "";
		u$u_is_operator = F;
		u$u_channels = chans;

		active_users[nick] = u;
		}

	for ( ch in chans )
		{
		if ( ch in active_channels )
			add (active_channels[ch]$c_users)[nick];
		else
			{
			local my_c: irc_channel;
			my_c$c_name = ch;
			add my_c$c_users[nick];
			my_c$c_type = "";
			my_c$c_modes = "";

			active_channels[ch] = my_c;
			}
		}
	}

event irc_oper_message(c: connection, user: string, password: string)
	{
	check_connection(c);
	log_activity(c, fmt("user requests operator status with name '%s', password '%s'",
				user, password));
	}

event irc_oper_response(c: connection, got_oper: bool)
	{
	check_connection(c);
	log_activity(c, fmt("user %s operator status",
				got_oper ? "received" : "did not receive"));
	}

event irc_kick_message(c: connection, prefix: string, chans: string,
			users: string, comment: string)
	{
	check_connection(c);
	log_activity(c, fmt("user '%s' requested to kick '%s' from channel(s) %s with comment %s",
				prefix, users, chans, comment));
	}

event irc_error_message(c: connection, prefix: string, message: string)
	{
	check_connection(c);
	log_activity(c, fmt("error message%s: %s",
				prefix == "" ? "" : fmt("from '%s'", prefix),
				message));
	}

event irc_invite_message(c: connection, prefix: string,
				nickname: string, channel: string)
	{
	check_connection(c);
	log_activity(c, fmt("'%s' invited to channel %s%s",
				nickname, channel,
				prefix == "" ? "" : fmt(" by %s", prefix)));
	}

event irc_mode_message(c: connection, prefix: string, params: string)
	{
	check_connection(c);
	log_activity(c, fmt("mode command%s: %s",
				prefix == "" ? "" : fmt(" from '%s'", prefix),
				params));
	}

event irc_squit_message(c: connection, prefix: string,
			server: string, message: string)
	{
	check_connection(c);

	log_activity(c, fmt("server disconnect attempt%s for %s with comment %s",
				prefix == "" ? "" : fmt(" from '%s'", prefix),
				server, message));
	}

event irc_names_info(c: connection, c_type: string, channel: string,
			users: string_set)
	{
	check_connection(c);

	local chan_type =
		c_type == "@" ? "secret" :
			(c_type == "*" ? "private" : "public");

	local message = fmt("channel '%s' (%s) contains users:",
				channel, chan_type);

	for ( user in users )
		message = fmt("%s %s", message, user);

	log_activity(c, message);

	if ( channel in active_channels )
		{
		for ( u in users )
			add (active_channels[channel]$c_users)[u];
		}
	else
		{
		local my_c: irc_channel;
		my_c$c_name = channel;
		my_c$c_users = users;
		my_c$c_type = "";
		my_c$c_modes = "";

		active_channels[channel] = my_c;
		}

	for ( nick in users )
		{
		if ( nick in active_users )
			add (active_users[nick]$u_channels)[channel];
		else
			{
			local usr: irc_user;
			usr$u_nick = nick;
			usr$u_real = "";
			usr$u_conn = c;
			usr$u_host = "";
			usr$u_is_operator = F;
			add usr$u_channels[channel];

			active_users[nick] = usr;
			}
		}
	}

event irc_dcc_message(c: connection, prefix: string, target: string,
			dcc_type: string, argument: string,
			address: addr, dest_port: count, size: count)
	{
	check_connection(c);

	log_activity(c, fmt("DCC %s invitation for '%s' to host %s on port %s%s",
				dcc_type, target, address, dest_port,
				dcc_type == "SEND" ?
					fmt(" (%s: %s bytes)", argument, size) :
					""));
	}

event irc_channel_topic(c: connection, channel: string, topic: string)
	{
	check_connection(c);
	log_activity(c, fmt("topic for %s is '%s'", channel, topic));
	}

event irc_password_message(c: connection, password: string)
	{
	check_connection(c);
	log_activity(c, fmt("password %s", password));
	}

function expired_user(t: table[string] of irc_user, idx: string): interval
	{
	for ( my_c in active_users[idx]$u_channels )
		{
		suspend_state_updates();
		delete active_channels[my_c]$c_users[idx];
		delete active_channels[my_c]$c_ops[idx];
		resume_state_updates();
		}

	return 0 secs;
	}

function expired_channel(t:table[string] of irc_channel, idx: string): interval
	{
	for ( my_u in active_channels[idx]$c_users )
		if ( my_u in active_users )
			delete active_users[my_u]$u_channels[idx];
		# Else is there a possible state leak?  How could it not
		# be in active_users?  Yet sometimes it isn't, which
		# is why we needed to add the above test.

	return 0 secs;
	}

function check_connection(c: connection)
	{
	if ( c$id !in conn_list )
		{
		++conn_ID;
		append_addl(c, fmt("#%d", conn_ID));
		conn_list[c$id] = conn_ID;

		log_activity(c, fmt("new connection %s", id_string(c$id)));
		}
	}
