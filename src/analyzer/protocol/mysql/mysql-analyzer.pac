refine flow MySQL_Flow += {
	function proc_mysql_handshakev10(msg: Handshake_v10): bool
		%{
		if ( mysql_server_version ) 
			BifEvent::generate_mysql_server_version(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
								bytestring_to_val(${msg.server_version}));
		connection()->bro_analyzer()->ProtocolConfirmation();
		return true;
		%}

	function proc_mysql_handshake_response_packet(msg: Handshake_Response_Packet): bool
		%{
		if ( mysql_handshake_response )
			BifEvent::generate_mysql_handshake_response(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
								    bytestring_to_val(${msg.username}));
		return true;
		%}

	function proc_mysql_command_request_packet(msg: Command_Request_Packet): bool
		%{
		if ( mysql_command_request )
			BifEvent::generate_mysql_command_request(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
								${msg.command}, bytestring_to_val(${msg.arg}));
		return true;
		%}

	function proc_err_packet(msg: ERR_Packet): bool
		%{
		if ( mysql_error )
			BifEvent::generate_mysql_error(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
						       ${msg.code}, bytestring_to_val(${msg.msg}));
		return true;
		%}

	function proc_ok_packet(msg: OK_Packet): bool
		%{
		if ( mysql_ok )
			BifEvent::generate_mysql_ok(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), ${msg.rows});
		return true;
		%}
	
	function proc_resultset(msg: Resultset): bool
		%{
		if ( mysql_command_response )
			BifEvent::generate_mysql_command_response(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), ${msg.rows}->size());
		return true;
		%}

};

refine typeattr Handshake_v10 += &let {
	proc = $context.flow.proc_mysql_handshakev10(this);
};

refine typeattr Handshake_Response_Packet += &let {
	proc = $context.flow.proc_mysql_handshake_response_packet(this);
};

refine typeattr Command_Request_Packet += &let {
	proc = $context.flow.proc_mysql_command_request_packet(this);
};

refine typeattr ERR_Packet += &let {
	proc = $context.flow.proc_err_packet(this);
};

refine typeattr OK_Packet += &let {
	proc = $context.flow.proc_ok_packet(this);
};

refine typeattr Resultset += &let {
	debug = $context.flow.proc_resultset(this);
};
