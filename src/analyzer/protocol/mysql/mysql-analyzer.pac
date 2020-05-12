# See the file "COPYING" in the main distribution directory for copyright.

refine flow MySQL_Flow += {
	function proc_mysql_initial_handshake_packet(msg: Initial_Handshake_Packet): bool
		%{
		if ( mysql_server_version )
			{
			if ( ${msg.version} == 10 )
				BifEvent::enqueue_mysql_server_version(connection()->bro_analyzer(),
				                                       connection()->bro_analyzer()->Conn(),
				                                       make_intrusive<StringVal>(c_str(${msg.handshake10.server_version})));
			if ( ${msg.version} == 9 )
				BifEvent::enqueue_mysql_server_version(connection()->bro_analyzer(),
				                                       connection()->bro_analyzer()->Conn(),
				                                       make_intrusive<StringVal>(c_str(${msg.handshake9.server_version})));
			}
		return true;
		%}

	function proc_mysql_handshake_response_packet(msg: Handshake_Response_Packet): bool
		%{
		if ( ${msg.version} == 9 || ${msg.version == 10} )
			connection()->bro_analyzer()->ProtocolConfirmation();

		if ( mysql_handshake )
			{
			if ( ${msg.version} == 10 )
				BifEvent::enqueue_mysql_handshake(connection()->bro_analyzer(),
				                                  connection()->bro_analyzer()->Conn(),
				                                  make_intrusive<StringVal>(c_str(${msg.v10_response.username})));
			if ( ${msg.version} == 9 )
				BifEvent::enqueue_mysql_handshake(connection()->bro_analyzer(),
				                                  connection()->bro_analyzer()->Conn(),
				                                  make_intrusive<StringVal>(c_str(${msg.v9_response.username})));
			}
		return true;
		%}

	function proc_mysql_command_request_packet(msg: Command_Request_Packet): bool
		%{
		if ( mysql_command_request )
			BifEvent::enqueue_mysql_command_request(connection()->bro_analyzer(),
			                                        connection()->bro_analyzer()->Conn(),
			                                        ${msg.command},
			                                        to_stringval(${msg.arg}));
		return true;
		%}

	function proc_err_packet(msg: ERR_Packet): bool
		%{
		if ( mysql_error )
			BifEvent::enqueue_mysql_error(connection()->bro_analyzer(),
			                              connection()->bro_analyzer()->Conn(),
			                              ${msg.code},
			                              to_stringval(${msg.msg}));
		return true;
		%}

	function proc_ok_packet(msg: OK_Packet): bool
		%{
		if ( mysql_ok )
			BifEvent::enqueue_mysql_ok(connection()->bro_analyzer(),
			                           connection()->bro_analyzer()->Conn(),
			                           ${msg.rows});
		return true;
		%}

	function proc_resultset(msg: Resultset): bool
		%{
		if ( connection()->get_results_seen() == 1 )
			{
			// This is a bit fake...
			if ( mysql_ok )
				BifEvent::enqueue_mysql_ok(connection()->bro_analyzer(),
				                           connection()->bro_analyzer()->Conn(),
				                           0);
			}

		if ( ${msg.is_eof} )
			return true;

		if ( ! mysql_result_row )
			return true;

		auto vt = zeek::vars::string_vec;
		auto vv = make_intrusive<VectorVal>(std::move(vt));

		auto& bstring = ${msg.row.first_field.val};
		auto ptr = reinterpret_cast<const char*>(bstring.data());
		vv->Assign(vv->Size(), make_intrusive<StringVal>(bstring.length(), ptr));

		auto& fields = *${msg.row.fields};

		for ( auto& f : fields )
			{
			auto& bstring = f->val();
			auto ptr = reinterpret_cast<const char*>(bstring.data());
			vv->Assign(vv->Size(), make_intrusive<StringVal>(bstring.length(), ptr));
			}

		BifEvent::enqueue_mysql_result_row(connection()->bro_analyzer(),
		                                   connection()->bro_analyzer()->Conn(),
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

refine typeattr Resultset += &let {
	proc = $context.flow.proc_resultset(this);
};
