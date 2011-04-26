# Notes
#   * irc_dcc_message doesn't seem to work.

@load functions

module IRC;

redef enum Log::ID += { IRC };

export {
	type Tags: enum { EMPTY };

	type Info: record {
		ts:       time        &log;
		id:       conn_id     &log;
		nick:     string      &log &optional;
		user:     string      &log &optional;
		channels: set[string] &log &optional;
		          
		command:  string      &log &optional;
		value:    string      &log &optional;
		addl:     string      &log &optional;
		tags:     set[Tags]   &log;
	};
	
	const logged_commands = set("JOIN", "DCC SEND");
	
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
	info$id = c$id;
	return info;
	}
	
function set_session(c: connection)
	{
	if ( ! c?$irc )
		c$irc = new_session(c);
		
	c$irc$ts=network_time();
	}
	
event irc_client(c: connection, prefix: string, data: string)
	{
	set_session(c);
	
	local parts = split1(data, / /);
	local command = parts[1];
	
	if ( /^PING/ !in data )
		{
		#print "irc_client";
		#print data;
		}
	}

event irc_server(c: connection, prefix: string, data: string)
	{
	set_session(c);
	
	local parts = split1(data, / /);
	local command = parts[1];
	
	if ( command == "PRIVMSG" )
		{
		local more_parts = split1(data, /\x01/);
		if ( |more_parts| > 1 )
			{
			if ( /^DCC/ in more_parts[1] )
				{
				
				}
			}
		#local p = split1(data, /:/);
		#if ( /DCC CHAT/ in data )
		#	print p;
		#expect_connection(c$id$resp_h, data$h, data$p, ANALYZER_FILE, 5 min);
		
		#print data;
		}
	}



event irc_nick_message(c: connection, who: string, newnick: string) &priority=5
	{
	c$irc$command="NICK";
	c$irc$value = newnick;
	
	Log::write(IRC, c$irc);
	
	c$irc$nick=newnick;
	}
	
event irc_nick_message(c: connection, who: string, newnick: string) &priority=-5
	{
	Log::write(IRC, c$irc);
	c$irc$nick=newnick;
	}

event irc_user_message(c: connection, user: string, host: string, server: string, real_name: string)
	{
	c$irc$command = "USER";
	c$irc$value = user;
	c$irc$addl=fmt("%s %s %s", host, server, real_name);
	}
	
event irc_user_message(c: connection, user: string, host: string, 
                       server: string, real_name: string) &priority=-5
	{
	Log::write(IRC, c$irc);
	c$irc$user = user;
	}
	
event irc_join_message(c: connection, info_list: irc_join_list) &priority=5
	{
	c$irc$command = "JOIN";
	}

event irc_join_message(c: connection, info_list: irc_join_list) &priority=-5
	{
	for ( l in info_list )
		{
		c$irc$value = l$channel;
		c$irc$addl = (l$password != "" ? fmt(" with channel key: '%s'", l$password) : "");
		Log::write(IRC, c$irc);
		}
	}