##! Implements base functionality for MySQL analysis. Generates the mysql.log file.

@load ./consts
@load base/protocols/conn/removal-hooks

module MySQL;

export {
	redef enum Log::ID += { mysql::LOG };

	global log_policy: Log::PolicyHook;

	type Info: record {
		## Timestamp for when the event happened.
		ts:     time    &log;
		## Unique ID for the connection.
		uid:    string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:     conn_id &log;
		## The command that was issued
		cmd:	string	&log;
		## The argument issued to the command
		arg:	string	&log;
		## Did the server tell us that the command succeeded?
		success: bool &log &optional;
		## The number of affected rows, if any
		rows: count &log &optional;
		## Server message, if any
		response: string &log &optional;
	};

	## Event that can be handled to access the MySQL record as it is sent on
	## to the logging framework.
	global log_mysql: event(rec: Info);

	## MySQL finalization hook.  Remaining MySQL info may get logged when it's called.
	global finalize_mysql: Conn::RemovalHook;

	## Well-known ports
	option ports = { 1434/tcp, 3306/tcp };
	redef likely_server_ports += { ports };
}

redef record connection += {
	mysql: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(mysql::LOG, [$columns=Info, $ev=log_mysql, $path="mysql", $policy=log_policy]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_MYSQL, ports);
	}

event mysql_handshake(c: connection, username: string)
	{
	if ( ! c?$mysql )
		{
		local info: Info;
		info$ts = network_time();
		info$uid = c$uid;
		info$id = c$id;
		info$cmd = "login";
		info$arg = username;
		c$mysql = info;
		Conn::register_removal_hook(c, finalize_mysql);
		}
	}

event mysql_command_request(c: connection, command: count, arg: string) &priority=5
	{
	if ( c?$mysql )
		{
		# We got a request, but we haven't logged our
		# previous request yet, so let's do that now.
		Log::write(mysql::LOG, c$mysql);
		delete c$mysql;
		}

	local info: Info;
	info$ts = network_time();
	info$uid = c$uid;
	info$id = c$id;
	info$cmd = commands[command];
	info$arg = sub(arg, /\0$/, "");
	c$mysql = info;
	Conn::register_removal_hook(c, finalize_mysql);
	}

event mysql_change_user(c: connection, username: string) &priority=5
	{
	c$mysql$arg = username;
	}

event mysql_command_request(c: connection, command: count, arg: string) &priority=-5
	{
	if ( c?$mysql && c$mysql?$cmd && c$mysql$cmd == "quit" )
		{
		# We get no response for quits, so let's just log it now.
		Log::write(mysql::LOG, c$mysql);
		delete c$mysql;
		}
	}

event mysql_error(c: connection, code: count, msg: string) &priority=5
	{
	if ( c?$mysql )
		{
		c$mysql$success = F;
		c$mysql$response = msg;
		}
	}

event mysql_error(c: connection, code: count, msg: string) &priority=-5
	{
	if ( c?$mysql )
		{
		Log::write(mysql::LOG, c$mysql);
		delete c$mysql;
		}
	}

event mysql_eof(c: connection, is_intermediate: bool) &priority=-5
	{
	if ( is_intermediate )
		return;

	if ( c?$mysql )
		{
		# We don't have more information, so just
		# place what mysql_ok() would've done.
		if ( ! c$mysql?$success )
			c$mysql$success = T;
		if ( ! c$mysql?$rows )
			c$mysql$rows = 0;

		Log::write(mysql::LOG, c$mysql);
		delete c$mysql;
		}
	}

event mysql_ok(c: connection, affected_rows: count) &priority=5
	{
	if ( c?$mysql )
		{
		c$mysql$success = T;
		c$mysql$rows = affected_rows;
		}
	}

event mysql_ok(c: connection, affected_rows: count) &priority=-5
	{
	if ( c?$mysql )
		{
		Log::write(mysql::LOG, c$mysql);
		delete c$mysql;
		}
	}

hook finalize_mysql(c: connection)
	{
	if ( c?$mysql )
		{
		Log::write(mysql::LOG, c$mysql);
		delete c$mysql;
		}
	}
