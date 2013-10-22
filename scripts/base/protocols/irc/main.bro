##! Implements the core IRC analysis support.  The logging model is to log
##! IRC commands along with the associated response and some additional 
##! metadata about the connection if it's available.

module IRC;

export {
	
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp when the command was seen.
		ts:       time        &log;
		## Unique ID for the connection.
		uid:      string      &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:       conn_id     &log;
		## Nickname given for the connection.
		nick:     string      &log &optional;
		## Username given for the connection.
		user:     string      &log &optional;
		
		## Command given by the client.
		command:  string      &log &optional;
		## Value for the command given by the client.
		value:    string      &log &optional;
		## Any additional data for the command.
		addl:     string      &log &optional;
	};
	
	## Event that can be handled to access the IRC record as it is sent on 
	## to the logging framework.
	global irc_log: event(rec: Info);
}

redef record connection += {
	## IRC session information.
	irc:  Info &optional;
};

const ports = { 6666/tcp, 6667/tcp, 6668/tcp, 6669/tcp };
redef likely_server_ports += { ports };

event bro_init() &priority=5
	{
	Log::create_stream(IRC::LOG, [$columns=Info, $ev=irc_log]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_IRC, ports);
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
		}
	}

event irc_nick_message(c: connection, is_orig: bool, who: string, newnick: string) &priority=-5
	{
	if ( is_orig )
		{
		Log::write(IRC::LOG, c$irc);
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
		}
	}

event irc_user_message(c: connection, is_orig: bool, user: string, host: string, server: string, real_name: string) &priority=-5
	{
	if ( is_orig )
		{
		Log::write(IRC::LOG, c$irc);
		c$irc$user = user;
		}
	}

event irc_join_message(c: connection, is_orig: bool, info_list: irc_join_list) &priority=5
	{
	set_session(c);
	if ( is_orig )
		c$irc$command = "JOIN";
	}

event irc_join_message(c: connection, is_orig: bool, info_list: irc_join_list) &priority=-5
	{
	if ( is_orig )
		{
		for ( l in info_list )
			{
			c$irc$value = l$channel;
			c$irc$addl = (l$password != "" ? fmt(" with channel key: '%s'", l$password) : "");
			Log::write(IRC::LOG, c$irc);
			}
		}
	}
