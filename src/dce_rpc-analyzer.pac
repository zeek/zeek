# DCE/RPC protocol data unit.

type DCE_RPC_PDU = record {
	# Set header's byteorder to little-endian (or big-endian) to
	# avoid cyclic dependency.
	header	: DCE_RPC_Header;
	frag	: bytestring &length = body_length;
	auth	: DCE_RPC_Auth(header);
} &let {
	body_length: int =
		 header.frag_length - sizeof(header) - header.auth_length;
	frag_reassembled: bool =
		$context.flow.reassemble_fragment(frag, header.lastfrag);
	body:	DCE_RPC_Body(header)
		withinput $context.flow.reassembled_body()
		&if frag_reassembled;
} &byteorder = header.byteorder,
  &length = header.frag_length;	# length of the PDU


connection DCE_RPC_Conn(bro_analyzer: BroAnalyzer) {
	upflow = DCE_RPC_Flow(true);
	downflow = DCE_RPC_Flow(false);

	function get_cont_id_opnum_map(cont_id: uint16): uint16
		%{
		return cont_id_opnum_map[cont_id];
		%}

	function set_cont_id_opnum_map(cont_id: uint16, opnum: uint16): bool
		%{
		cont_id_opnum_map[cont_id] = opnum;
		return true;
		%}

	%member{
	map<uint16, uint16> cont_id_opnum_map;
	%}
};


flow DCE_RPC_Flow(is_orig: bool) {
	flowunit = DCE_RPC_PDU withcontext (connection, this);

	%member{
	FlowBuffer frag_reassembler_;
	%}

	# Fragment reassembly.
	function reassemble_fragment(frag: bytestring, lastfrag: bool): bool
		%{
		int orig_data_length = frag_reassembler_.data_length();

		frag_reassembler_.NewData(frag.begin(), frag.end());

		int new_frame_length = orig_data_length + frag.length();
		if ( orig_data_length == 0 )
			frag_reassembler_.NewFrame(new_frame_length, false);
		else
			frag_reassembler_.GrowFrame(new_frame_length);

		return lastfrag;
		%}

	function reassembled_body(): const_bytestring
		%{
		return const_bytestring(
			frag_reassembler_.begin(),
			frag_reassembler_.end());
		%}

	# Bind.
	function process_dce_rpc_bind(bind: DCE_RPC_Bind): bool
		%{
		$const_def{bind_elems = bind.p_context_elem};

		if ( ${bind_elems.n_context_elem} > 1 ) {
			${connection.bro_analyzer}->Weird(
				"DCE_RPC_bind_to_multiple_interfaces");
		}

		if ( dce_rpc_bind ) {
			// Go over the elements, each having a UUID
			for ( int i = 0; i < ${bind_elems.n_context_elem}; ++i ) {
				$const_def{if_uuid =
					bind_elems.p_cont_elem[i].abstract_syntax.if_uuid};

				// Queue the event
				BifEvent::generate_dce_rpc_bind(
					${connection.bro_analyzer},
					${connection.bro_analyzer}->Conn(),
					bytestring_to_val(${if_uuid}));

				// Set the connection's UUID
				// ${connection}->set_uuid(${if_uuid});
			}
		}

		return ${bind_elems.n_context_elem} > 0;
		%}

	# Request.
	function process_dce_rpc_request(req: DCE_RPC_Request): bool
		%{
		if ( dce_rpc_request )
			{
			BifEvent::generate_dce_rpc_request(
				${connection.bro_analyzer},
				${connection.bro_analyzer}->Conn(),
				${req.opnum},
				bytestring_to_val(${req.stub}));
			}

		${connection}->set_cont_id_opnum_map(${req.p_cont_id},
							${req.opnum});

		return true;
		%}

	# Response.
	function process_dce_rpc_response(resp: DCE_RPC_Response): bool
		%{
		if ( dce_rpc_response )
			{
			BifEvent::generate_dce_rpc_response(
				${connection.bro_analyzer},
				${connection.bro_analyzer}->Conn(),
				${connection}->get_cont_id_opnum_map(${resp.p_cont_id}),
				bytestring_to_val(${resp.stub}));
			}

		return true;
		%}
};
