
refine connection DCE_RPC_Conn += {
	%member{
		map<uint16, uint16> cont_id_opnum_map;
		uint64 fid;
	%}

	%init{
		fid = 0;
	%}

	function set_file_id(fid_in: uint64): bool
		%{
		fid = fid_in;
		return true;
		%}

	function get_cont_id_opnum_map(cont_id: uint16): uint16
		%{
		return cont_id_opnum_map[cont_id];
		%}

	function set_cont_id_opnum_map(cont_id: uint16, opnum: uint16): bool
		%{
		cont_id_opnum_map[cont_id] = opnum;
		return true;
		%}

	function proc_dce_rpc_pdu(pdu: DCE_RPC_PDU): bool
		%{
		// If a whole pdu message parsed ok, let's confirm the protocol
		zeek_analyzer()->AnalyzerConfirmation();
		return true;
		%}

	function proc_dce_rpc_message(header: DCE_RPC_Header): bool
		%{
		if ( dce_rpc_message )
			{
			zeek::BifEvent::enqueue_dce_rpc_message(zeek_analyzer(),
			                                  zeek_analyzer()->Conn(),
			                                  ${header.is_orig},
			                                  fid,
			                                  ${header.PTYPE},
			                                  zeek::BifType::Enum::DCE_RPC::PType->GetEnumVal(${header.PTYPE}));
			}
		return true;
		%}

	function process_dce_rpc_bind(req: ContextRequest): bool
		%{
		if ( dce_rpc_bind )
			{
			zeek::BifEvent::enqueue_dce_rpc_bind(zeek_analyzer(),
			                               zeek_analyzer()->Conn(),
			                               fid,
			                               ${req.id},
			                               to_stringval(${req.abstract_syntax.uuid}),
			                               ${req.abstract_syntax.ver_major},
			                               ${req.abstract_syntax.ver_minor});
			}

		return true;
		%}

	function process_dce_rpc_alter_context(req: ContextRequest): bool
		%{
		if ( dce_rpc_alter_context )
			{
			zeek::BifEvent::enqueue_dce_rpc_alter_context(zeek_analyzer(),
			                                        zeek_analyzer()->Conn(),
			                                        fid,
			                                        ${req.id},
			                                        to_stringval(${req.abstract_syntax.uuid}),
			                                        ${req.abstract_syntax.ver_major},
			                                        ${req.abstract_syntax.ver_minor});
			}

		return true;
		%}

	function process_dce_rpc_bind_ack(bind: DCE_RPC_Bind_Ack): bool
		%{
		if ( dce_rpc_bind_ack )
			{
			zeek::StringValPtr sec_addr;

			// Remove the null from the end of the string if it's there.
			if ( ${bind.sec_addr}.length() > 0 &&
			     *(${bind.sec_addr}.begin() + ${bind.sec_addr}.length()) == 0 )
				sec_addr = zeek::make_intrusive<zeek::StringVal>(${bind.sec_addr}.length()-1, (const char*) ${bind.sec_addr}.begin());
			else
				sec_addr = zeek::make_intrusive<zeek::StringVal>(${bind.sec_addr}.length(), (const char*) ${bind.sec_addr}.begin());

			zeek::BifEvent::enqueue_dce_rpc_bind_ack(zeek_analyzer(),
			                                   zeek_analyzer()->Conn(),
			                                   fid,
			                                   std::move(sec_addr));
			}
		return true;
		%}

	function process_dce_rpc_alter_context_resp(bind: DCE_RPC_AlterContext_Resp): bool
		%{
		if ( dce_rpc_alter_context_resp )
			{
			zeek::BifEvent::enqueue_dce_rpc_alter_context_resp(zeek_analyzer(),
			                                             zeek_analyzer()->Conn(),
			                                             fid);
			}
		return true;
		%}

	function process_dce_rpc_request(req: DCE_RPC_Request): bool
		%{
		if ( dce_rpc_request )
			{
			zeek::BifEvent::enqueue_dce_rpc_request(zeek_analyzer(),
			                                  zeek_analyzer()->Conn(),
			                                  fid,
			                                  ${req.context_id},
			                                  ${req.opnum},
			                                  ${req.stub}.length());
			}

		if ( dce_rpc_request_stub )
			zeek::BifEvent::enqueue_dce_rpc_request_stub(zeek_analyzer(),
			                                  zeek_analyzer()->Conn(),
			                                  fid,
			                                  ${req.context_id},
			                                  ${req.opnum},
			                                  binpac::to_stringval(${req.stub}));

		set_cont_id_opnum_map(${req.context_id},
		                      ${req.opnum});
		return true;
		%}

	function process_dce_rpc_response(resp: DCE_RPC_Response): bool
		%{
		if ( dce_rpc_response )
			{
			zeek::BifEvent::enqueue_dce_rpc_response(zeek_analyzer(),
			                                   zeek_analyzer()->Conn(),
			                                   fid,
			                                   ${resp.context_id},
			                                   get_cont_id_opnum_map(${resp.context_id}),
			                                   ${resp.stub}.length());
			}

		if ( dce_rpc_response_stub )
			zeek::BifEvent::enqueue_dce_rpc_response_stub(zeek_analyzer(),
			                                   zeek_analyzer()->Conn(),
			                                   fid,
			                                   ${resp.context_id},
			                                   get_cont_id_opnum_map(${resp.context_id}),
			                                   binpac::to_stringval(${resp.stub}));

		return true;
		%}

};

refine typeattr DCE_RPC_PDU += &let {
	proc = $context.connection.proc_dce_rpc_pdu(this);
}

refine typeattr DCE_RPC_Header += &let {
	proc = $context.connection.proc_dce_rpc_message(this);
};

refine typeattr ContextRequest += &let {
	proc = case ptype of {
		DCE_RPC_BIND          -> $context.connection.process_dce_rpc_bind(this);
		DCE_RPC_ALTER_CONTEXT -> $context.connection.process_dce_rpc_alter_context(this);
	};
};

refine typeattr DCE_RPC_Bind_Ack += &let {
	proc = $context.connection.process_dce_rpc_bind_ack(this);
};

refine typeattr DCE_RPC_AlterContext_Resp += &let {
	proc = $context.connection.process_dce_rpc_alter_context_resp(this);
};

refine typeattr DCE_RPC_Request += &let {
	proc = $context.connection.process_dce_rpc_request(this);
};

refine typeattr DCE_RPC_Response += &let {
	proc = $context.connection.process_dce_rpc_response(this);
};
