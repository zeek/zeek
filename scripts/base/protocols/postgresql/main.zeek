##! Implements base functionality for PostgreSQL analysis.

@load ./consts
@load ./spicy-events

@load base/protocols/conn/removal-hooks

module PostgreSQL;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	type Version: record {
		major: count;
		minor: count;
	};

	## Record type containing the column fields of the PostgreSQL log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;

		## The user as found in the StartupMessage.
		user: string &optional &log;
		## The database as found in the StartupMessage.
		database: string &optional &log;
		## The application name as found in the StartupMessage.
		application_name: string &optional &log;

		# The command or message from the frontend.
		frontend: string &optional &log;
		# Arguments for the command.
		frontend_arg: string &optional &log;
		# The reply from the backend.
		backend: string &optional &log;
		# Arguments for the reply from the backend.
		backend_arg: string &optional &log;

		# Whether the login/query was successful.
		success: bool &optional &log;

		# The number of rows returned or affectd.
		rows: count &optional &log;
	};

	type State: record {
		version: Version &optional;
		user: string &optional;
		database: string &optional;
		application_name: string &optional;
		rows: count &optional;
		errors: vector of string;
	};

	## Default hook into PostgreSQL logging.
	global log_postgresql: event(rec: Info);

	global finalize_postgresql: Conn::RemovalHook;

	global ports: set[port] = { 5432/tcp } &redef;
}

redef record connection += {
	postgresql: Info &optional;
	postgresql_state: State &optional;
};

redef likely_server_ports += { ports };

event zeek_init() {
	Analyzer::register_for_ports(Analyzer::ANALYZER_POSTGRESQL, ports);

	Log::create_stream(PostgreSQL::LOG, Log::Stream($columns=Info, $ev=log_postgresql, $path="postgresql"));
}

hook set_session(c: connection) {
	if ( ! c?$postgresql )
		c$postgresql = Info($ts=network_time(), $uid=c$uid, $id=c$id);

	if ( ! c?$postgresql_state ) {
		c$postgresql_state = State();
		Conn::register_removal_hook(c, finalize_postgresql);
	}
}

function emit_log(c: connection) {
	if ( ! c?$postgresql )
		return;

	if ( c$postgresql_state?$user )
		c$postgresql$user = c$postgresql_state$user;

	if ( c$postgresql_state?$database )
		c$postgresql$database = c$postgresql_state$database;

	if ( c$postgresql_state?$application_name )
		c$postgresql$application_name = c$postgresql_state$application_name;

	Log::write(PostgreSQL::LOG, c$postgresql);
	delete c$postgresql;
}

event PostgreSQL::ssl_request(c: connection) {
	hook set_session(c);

	c$postgresql$frontend = "ssl_request";
}

event PostgreSQL::ssl_reply(c: connection, b: string) {
	hook set_session(c);

	c$postgresql$backend = "ssl_reply";
	c$postgresql$backend_arg = b;
	c$postgresql$success = b == "S";

	emit_log(c);
}

event PostgreSQL::startup_parameter(c: connection, name: string, value: string) {
	hook set_session(c);

	if ( name == "user" ) {
		c$postgresql_state$user = value;
	} else if ( name == "database" ) {
		c$postgresql_state$database = value;
	} else if ( name== "application_name" ) {
		c$postgresql_state$application_name = value;
	}
}

event PostgreSQL::startup_message(c: connection, major: count, minor: count) {
	hook set_session(c);

	c$postgresql_state$version = Version($major=major, $minor=minor);
	c$postgresql$frontend = "startup";
}

event PostgreSQL::error_response_identified_field(c: connection, code: string, value: string) {
	hook set_session(c);

	local errors = c$postgresql_state$errors;
	errors += fmt("%s=%s", error_ids[code], value);
}

event PostgreSQL::notice_response_identified_field(c: connection, code: string, value: string) {
	hook set_session(c);

	local notice = fmt("%s=%s", error_ids[code], value);
	if ( c$postgresql?$backend_arg )
		c$postgresql$backend_arg += "," + notice;
	else
		c$postgresql$backend_arg = notice;
}

event PostgreSQL::error_response(c: connection) {
	hook set_session(c);

	if ( c$postgresql?$backend )
		c$postgresql$backend += ",error";
	else
		c$postgresql$backend = "error";

	local errors = join_string_vec(c$postgresql_state$errors, ",");
	c$postgresql_state$errors = vector();

	if ( c$postgresql?$backend_arg )
		c$postgresql$backend_arg += "," + errors;
	else
		c$postgresql$backend_arg = errors;

	c$postgresql$success = F;

	emit_log(c);
}

event PostgreSQL::authentication_request(c: connection, identifier: count, data: string) {
	hook set_session(c);

	if ( c$postgresql?$backend && ! ends_with(c$postgresql$backend, "auth") )
		c$postgresql$backend += ",auth_request";
	else
		c$postgresql$backend = "auth_request";

	if ( c$postgresql?$backend_arg )
		c$postgresql$backend_arg += "," + auth_ids[identifier];
	else
		c$postgresql$backend_arg = auth_ids[identifier];
}

event PostgreSQL::authentication_ok(c: connection) {
	hook set_session(c);

	c$postgresql$backend = "auth_ok";
	c$postgresql$success = T;
}

event PostgreSQL::terminate(c: connection) {
	if ( c?$postgresql )
		emit_log(c);

	hook set_session(c);
	c$postgresql$frontend = "terminate";
	emit_log(c);
}

event PostgreSQL::simple_query(c: connection, query: string) {
	if ( c?$postgresql )
		emit_log(c);

	hook set_session(c);

	c$postgresql$frontend = "simple_query";
	c$postgresql$frontend_arg = query;
	c$postgresql_state$rows = 0;
}

event PostgreSQL::data_row(c: connection, column_values: count) {
	hook set_session(c);

	if ( ! c$postgresql_state?$rows )
		c$postgresql_state$rows = 0;

	++c$postgresql_state$rows;
}

event PostgreSQL::ready_for_query(c: connection, transaction_status: string) {
	# Log a query (if there was one).
	if ( ! c?$postgresql )
		return;

	# If no one said otherwise, the last action was successful.
	if ( ! c$postgresql?$success )
		c$postgresql$success = transaction_status == "I" || transaction_status == "T";

	if ( c$postgresql_state?$rows ) {
		c$postgresql$rows = c$postgresql_state$rows;
		delete c$postgresql_state$rows;
	}

	emit_log(c);
}

hook finalize_postgresql(c: connection) &priority=-5 {
	emit_log(c);
}
