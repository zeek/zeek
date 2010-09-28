# $Id: irc-bot-syslog.bro,v 1.1.4.2 2006/05/31 00:16:21 sommer Exp $
#
# Passes current bot-state to syslog.
#
# - When a new server/client is found, we syslog it immediately.
# - Every IrcBot::summary_interval we dump the current set.

@load irc-bot

module IrcBotSyslog;

export {
	# Prefix for all messages for easy grepping.
	const prefix = "irc-bots" &redef;
}

# For debugging, everything which goes to syslog also goes here.
global syslog_file = open_log_file("irc-bots.syslog");

function fmt_time(t: time) : string
	{
	return strftime("%Y-%m-%d-%H-%M-%S", t);
	}

function log_server(ip: addr, new: bool)
	{
	local s = IrcBot::servers[ip];
	local ports = IrcBot::portset_to_str(s$p);

	local msg = fmt("%s ip=%s new=%d local=%d server=1 first_seen=%s last_seen=%s ports=%s",
			prefix, ip, new, is_local_addr(ip),
			fmt_time(s$first_seen), fmt_time(s$last_seen), ports);

	syslog(msg);
	print syslog_file, fmt("%.6f %s", network_time(), msg);
	}

function log_client(ip: addr, new: bool)
	{
	local c = IrcBot::clients[ip];
	local servers = IrcBot::addrset_to_str(c$servers);

	local msg = fmt("%s ip=%s new=%d local=%d server=0 first_seen=%s last_seen=%s user=%s nick=%s realname=%s servers=%s",
			prefix, ip, new, is_local_addr(ip),
			fmt_time(c$first_seen), fmt_time(c$last_seen),
				  c$user, c$nick, c$realname, servers);

	syslog(msg);
	print syslog_file, fmt("%.6f %s", network_time(), msg);
	}

event print_bot_state()
	{
	for ( s in IrcBot::confirmed_bot_servers )
		log_server(s, F);

	for ( c in IrcBot::confirmed_bot_clients )
		log_client(c, F);
	}

event bro_init()
	{
	set_buf(syslog_file, F);
	}

redef notice_policy += {
	[$pred(a: notice_info) =
		{
		if ( a$note == IrcBot::IrcBotServerFound )
			log_server(a$src, T);

		if ( a$note == IrcBot::IrcBotClientFound )
			log_client(a$src, T);

		return F;
		},
	 $result = NOTICE_FILE,
	 $priority = 1]
};
