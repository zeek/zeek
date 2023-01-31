# See the file "COPYING" in the main distribution directory for copyright.

refine flow MySQL_Flow += {
	function proc_mysql_initial_handshake_packet(msg: Initial_Handshake_Packet): bool
		%{
		if ( mysql_server_version )
			{
			if ( ${msg.version} == 10 )
				zeek::BifEvent::enqueue_mysql_server_version(connection()->zeek_analyzer(),
				                                       connection()->zeek_analyzer()->Conn(),
				                                       zeek::make_intrusive<zeek::StringVal>(c_str(${msg.handshake10.server_version})));
			if ( ${msg.version} == 9 )
				zeek::BifEvent::enqueue_mysql_server_version(connection()->zeek_analyzer(),
				                                       connection()->zeek_analyzer()->Conn(),
				                                       zeek::make_intrusive<zeek::StringVal>(c_str(${msg.handshake9.server_version})));
			}
		return true;
		%}

	function proc_mysql_handshake_response_packet(msg: Handshake_Response_Packet): bool
		%{
		if ( ${msg.version} == 9 || ${msg.version == 10} )
			connection()->zeek_analyzer()->AnalyzerConfirmation();

		// If the client requested SSL and didn't provide credentials, switch to SSL
		if ( ${msg.version} == 10 && ( ${msg.v10_response.cap_flags} & CLIENT_SSL ) && ${msg.v10_response.credentials}->empty() )
			{
			connection()->zeek_analyzer()->StartTLS();
			return true;
			}

		if ( mysql_handshake )
			{
			if ( ${msg.version} == 10 && ${msg.v10_response.credentials}->size() > 0 )
				zeek::BifEvent::enqueue_mysql_handshake(connection()->zeek_analyzer(),
				                                  connection()->zeek_analyzer()->Conn(),
				                                  zeek::make_intrusive<zeek::StringVal>(c_str(${msg.v10_response.credentials[0].username})));
			if ( ${msg.version} == 9 )
				zeek::BifEvent::enqueue_mysql_handshake(connection()->zeek_analyzer(),
				                                  connection()->zeek_analyzer()->Conn(),
				                                  zeek::make_intrusive<zeek::StringVal>(c_str(${msg.v9_response.username})));
			}
		return true;
		%}

	function proc_mysql_command_request_packet(msg: Command_Request_Packet): bool
		%{
		if ( mysql_command_request )
			zeek::BifEvent::enqueue_mysql_command_request(connection()->zeek_analyzer(),
			                                        connection()->zeek_analyzer()->Conn(),
			                                        ${msg.command},
			                                        to_stringval(${msg.arg}));
		return true;
		%}

	function proc_err_packet(msg: ERR_Packet): bool
		%{
		if ( mysql_error )
			zeek::BifEvent::enqueue_mysql_error(connection()->zeek_analyzer(),
			                              connection()->zeek_analyzer()->Conn(),
			                              ${msg.code},
			                              to_stringval(${msg.msg}));
		return true;
		%}

	function proc_ok_packet(msg: OK_Packet): bool
		%{
		if ( mysql_ok )
			zeek::BifEvent::enqueue_mysql_ok(connection()->zeek_analyzer(),
			                           connection()->zeek_analyzer()->Conn(),
			                           ${msg.rows});
		return true;
		%}

	function proc_eof_packet(msg: EOF_Packet): bool
		%{
		if ( mysql_eof )
			zeek::BifEvent::enqueue_mysql_eof(connection()->zeek_analyzer(),
			                                  connection()->zeek_analyzer()->Conn(),
			                                  ${msg.typ} == EOF_INTERMEDIATE);
		return true;
		%}

	function proc_resultset(msg: Resultset): bool
		%{
		if ( ${msg.is_eof} )
			return true;  // Raised through proc_eof_packet()

		if ( ! mysql_result_row )
			return true;

		auto vt = zeek::id::string_vec;
		auto vv = zeek::make_intrusive<zeek::VectorVal>(std::move(vt));

		auto& bstring = ${msg.row.first_field.val};
		auto ptr = reinterpret_cast<const char*>(bstring.data());
		vv->Assign(vv->Size(), zeek::make_intrusive<zeek::StringVal>(bstring.length(), ptr));

		auto& fields = *${msg.row.fields};

		for ( auto& f : fields )
			{
			auto& bstring = f->val();
			auto ptr = reinterpret_cast<const char*>(bstring.data());
			vv->Assign(vv->Size(), zeek::make_intrusive<zeek::StringVal>(bstring.length(), ptr));
			}

		zeek::BifEvent::enqueue_mysql_result_row(connection()->zeek_analyzer(),
		                                   connection()->zeek_analyzer()->Conn(),
		                                   std::move(vv));

		return true;
		%}

};

refine typeattr Initial_Handshake_Packet += &let {
	proc = $context.flow.proc_mysql_initial_handshake_packet(this);
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

refine typeattr EOF_Packet += &let {
	proc = $context.flow.proc_eof_packet(this);
};

refine typeattr Resultset += &let {
	proc = $context.flow.proc_resultset(this);
};
