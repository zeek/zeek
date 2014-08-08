##! Implements base functionality for MySQL analysis. Generates the mysql.log file.

module MySQL;

export {
	redef enum Log::ID += { mysql::LOG };

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
		## The result (error, OK, etc.) from the server
		result: string &log &optional;
		## Server message, if any
		response: string &log &optional;
	};

	## Event that can be handled to access the MySQL record as it is sent on
	## to the logging framework.
	global log_mysql: event(rec: Info);
}

redef record connection += {
	mysql: Info &optional;
};

const ports = { 1434/tcp, 3306/tcp };

const commands: table[count] of string = {
	[0]  = "sleep",
	[1]  = "quit",
	[2]  = "init_db",
	[3]  = "query",
	[4]  = "field_list",
	[5]  = "create_db",
	[6]  = "drop_db",
	[7]  = "refresh",
	[8]  = "shutdown",
	[9]  = "statistics",
	[10] = "process_info",
	[11] = "connect",
	[12] = "process_kill",
	[13] = "debug",
	[14] = "ping",
	[15] = "time",
	[16] = "delayed_insert",
	[17] = "change_user",
	[18] = "binlog_dump",
	[19] = "table_dump",
	[20] = "connect_out",
	[21] = "register_slave",
	[22] = "stmt_prepare",
	[23] = "stmt_execute",
	[24] = "stmt_send_long_data",
	[25] = "stmt_close",
	[26] = "stmt_reset",
	[27] = "set_option",
	[28] = "stmt_fetch",
	[29] = "daemon",
	[30] = "binlog_dump_gtid",
	[31] = "reset_connection",
} &default=function(i: count): string { return fmt("unknown-%d", i); };

event bro_init() &priority=5
	{
	Log::create_stream(mysql::LOG, [$columns=Info, $ev=log_mysql]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_MYSQL, ports);
	}

event mysql_handshake_response(c: connection, username: string)
	{
	if ( !c?$mysql )
		{
		local info: Info;
		info$ts = network_time();
		info$uid = c$uid;
		info$id = c$id;
		info$cmd = "login";
		info$arg = username;
		c$mysql = info;
		}
	}

event mysql_command_request(c: connection, command: count, arg: string)
	{
	if ( !c?$mysql )
		{
		local info: Info;
		info$ts = network_time();
		info$uid = c$uid;
		info$id = c$id;
		info$cmd = commands[command];
		info$arg = sub(arg, /\0$/, "");
		c$mysql = info;
		if ( command == 1 )
			{
			# We get no response for quits, so let's just log it now.
			Log::write(mysql::LOG, c$mysql);
			delete c$mysql;			
			}
		}
	}

event mysql_command_response(c: connection, response: count)
	{
	if ( c?$mysql )
		{
		c$mysql$result = "ok";
		c$mysql$response = fmt("Affected rows: %d", response);
		Log::write(mysql::LOG, c$mysql);
		delete c$mysql;
		}
	}

event mysql_error(c: connection, code: count, msg: string)
	{
	if ( c?$mysql )
		{
		c$mysql$result = "error";
		c$mysql$response = msg;
		Log::write(mysql::LOG, c$mysql);
		delete c$mysql;
		}	
	}

event mysql_ok(c: connection, affected_rows: count)
	{
	if ( c?$mysql )
		{
		c$mysql$result = "ok";
		c$mysql$response = fmt("Affected rows: %d", affected_rows);
		Log::write(mysql::LOG, c$mysql);
		delete c$mysql;
		}	
	}