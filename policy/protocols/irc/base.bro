##! This is the script that implements the core IRC analysis support.  It only
##! logs a very limited subset of the IRC protocol by default.  The points
##! that it logs at are NICK commands, USER commands, and JOIN commands.  It 
##! log various bits of meta data as indicated in the :bro:type:`Info` record
##! along with the command at the command arguments.

module IRC;

export {
	redef enum Log::ID += { IRC };

	type Tag: enum { 
		EMPTY 
	};

	type Info: record {
		ts:       time        &log;
		uid:      string      &log;
		id:       conn_id     &log;
		nick:     string      &log &optional;
		user:     string      &log &optional;
		channels: set[string] &log &optional;
		          
		command:  string      &log &optional;
		value:    string      &log &optional;
		addl:     string      &log &optional;
		tags:     set[Tag]    &log;
	};
	
	global irc_log: event(rec: Info);
}

redef record connection += {
	irc:  Info &optional;
};

# Some common IRC ports.
redef capture_filters += { ["irc-6666"] = "port 6666" };
redef capture_filters += { ["irc-6667"] = "port 6667" };

# DPD configuration.
global irc_ports = { 6666/tcp, 6667/tcp } &redef;
redef dpd_config += { [ANALYZER_IRC] = [$ports = irc_ports] };

event bro_init()
	{
	Log::create_stream(IRC, [$columns=Info, $ev=irc_log]);
	}
	
function new_session(c: connection): Info
	{
	local info: Info;
	info$ts = network_time();
	info$uid = c$uid;
	info$id = c$id;
	return info;
	}
	
function set_session(c: connection)
	{
	if ( ! c?$irc )
		c$irc = new_session(c);
		
	c$irc$ts=network_time();
	}

event irc_nick_message(c: connection, is_orig: bool, who: string, newnick: string) &priority=5
	{
	set_session(c);
	if ( is_orig )
		{
		c$irc$command = "NICK";
		c$irc$value = newnick;
		Log::write(IRC, c$irc);
		c$irc$nick  = newnick;
		}
	}

event irc_user_message(c: connection, is_orig: bool, user: string, host: string, server: string, real_name: string) &priority=5
	{
	set_session(c);
	if ( is_orig )
		{
		c$irc$command = "USER";
		c$irc$value = user;
		c$irc$addl=fmt("%s %s %s", host, server, real_name);
		Log::write(IRC, c$irc);
		c$irc$user = user;
		}
	}

event irc_join_message(c: connection, is_orig: bool, info_list: irc_join_list) &priority=5
	{
	set_session(c);
	if ( is_orig )
		{
		c$irc$command = "JOIN";
		for ( l in info_list )
			{
			c$irc$value = l$channel;
			c$irc$addl = (l$password != "" ? fmt(" with channel key: '%s'", l$password) : "");
			Log::write(IRC, c$irc);
			}
		}
	}
