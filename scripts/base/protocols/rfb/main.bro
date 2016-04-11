module Rfb;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp for when the event happened.
		ts:     time    &log;
		## Unique ID for the connection.
		uid:    string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:     conn_id &log;

		client_major_version: string &log &optional;
		client_minor_version: string &log &optional;
		server_major_version: string &log &optional;
		server_minor_version: string &log &optional;

		authentication_method: string &log &optional;
		auth: bool &log &optional;

		share_flag: bool &log &optional;
		desktop_name: string &log &optional;
		width: count &log &optional;
		height: count &log &optional;

		done: bool  &default=F;
	};

	global log_rfb: event(rec: Info);
}

function friendly_auth_name(auth: count): string {
	switch (auth) {
		case 0:
			return "Invalid";
		case 1:
			return "None";
		case 2:
			return "VNC";
		case 16:
			return "Tight";
		case 17:
			return "Ultra";
		case 18:
			return "TLS";
		case 19:
			return "VeNCrypt";
		case 20:
			return "GTK-VNC SASL";
		case 21:
			return "MD5 hash authentication";
		case 22:
			return "Colin Dean xvp";
		case 30:
			return "Apple Remote Desktop";
	}
	return "RealVNC";

}


redef record connection += {
	rfb_state: Info &optional;
};

event bro_init() &priority=5
	{
	Log::create_stream(Rfb::LOG, [$columns=Info, $ev=log_rfb, $path="rfb"]);
	}

function write_log(c:connection) {
	local state = c$rfb_state;
	if ( state?$done && state$done == T) {
		return;
	}
	Log::write(Rfb::LOG, c$rfb_state);
	c$rfb_state$done = T;
}

function set_session(c: connection) {
	if ( ! c?$rfb_state ) {
		local info: Info;
		info$ts  = network_time();
		info$uid = c$uid;
		info$id  = c$id;

		c$rfb_state = info;
	}
	}

event rfb_event(c: connection)
	{
		set_session(c);
	}

event rfb_client_version(c: connection, major_version: string, minor_version: string)
	{
	set_session(c);
	c$rfb_state$client_major_version = major_version;
	c$rfb_state$client_minor_version = minor_version;
	}

event rfb_server_version(c: connection, major_version: string, minor_version: string)
	{
	set_session(c);
	c$rfb_state$server_major_version = major_version;
	c$rfb_state$server_minor_version = minor_version;
	}

event rfb_authentication_type(c: connection, authtype: count)
	{
	c$rfb_state$authentication_method = friendly_auth_name(authtype);
	}

event rfb_server_parameters(c: connection, name: string, width: count, height: count)
	{
	c$rfb_state$desktop_name = name;
	c$rfb_state$width = width;
	c$rfb_state$height = height;
	write_log(c);
	}

event rfb_auth_result(c: connection, result: count)
	{
	if ( result ==0 ) {
		c$rfb_state$auth = T;
	} else {
		c$rfb_state$auth = F;
	}
	}

event rfb_share_flag(c: connection, flag: bool)
	{
	c$rfb_state$share_flag = flag;
	}

event connection_state_remove(c: connection) {
	if ( c?$rfb_state ) {
	write_log(c);
	}
}
