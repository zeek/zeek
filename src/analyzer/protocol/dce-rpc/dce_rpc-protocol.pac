# Definitions for DCE RPC.

enum dce_rpc_ptype {
	DCE_RPC_REQUEST,
	DCE_RPC_PING,
	DCE_RPC_RESPONSE,
	DCE_RPC_FAULT,
	DCE_RPC_WORKING,
	DCE_RPC_NOCALL,
	DCE_RPC_REJECT,
	DCE_RPC_ACK,
	DCE_RPC_CL_CANCEL,
	DCE_RPC_FACK,
	DCE_RPC_CANCEL_ACK,
	DCE_RPC_BIND,
	DCE_RPC_BIND_ACK,
	DCE_RPC_BIND_NAK,
	DCE_RPC_ALTER_CONTEXT,
	DCE_RPC_ALTER_CONTEXT_RESP,
	DCE_RPC_AUTH3,
	DCE_RPC_SHUTDOWN,
	DCE_RPC_CO_CANCEL,
	DCE_RPC_ORPHANED,
	DCE_RPC_RTS,
};

type uuid = bytestring &length = 16;

type context_handle = record {
	attrs : uint32;
	uuid  : bytestring &length = 16;
};

type DCE_RPC_PDU(is_orig: bool) = record {
	header  : DCE_RPC_Header(is_orig);
	frag    : bytestring &length=body_length;
	auth    : DCE_RPC_Auth_wrapper(header);
} &let {
	# Subtract an extra 8 when there is an auth section because we have some "auth header" fields in that structure.
	body_length      : int  = header.frag_length - sizeof(header) - header.auth_length - (header.auth_length > 0 ? 8 : 0);
	frag_reassembled : bool = $context.flow.reassemble_fragment(header, frag);
	body             : DCE_RPC_Body(header) withinput $context.flow.reassembled_body(header, frag) &if(frag_reassembled);
} &byteorder = header.byteorder, &length = header.frag_length;

type NDR_Format = record {
	intchar    : uint8;
	floatspec  : uint8;
	reserved   : padding[2];
} &let {
	byteorder = (intchar >> 4) ? littleendian : bigendian;
};

type DCE_RPC_Header(is_orig: bool) = record {
	rpc_vers       : uint8 &enforce(rpc_vers == 5);
	rpc_vers_minor : uint8;
	PTYPE          : uint8;
	pfc_flags      : uint8;
	packed_drep    : NDR_Format;
	frag_length    : uint16;
	auth_length    : uint16;
	call_id        : uint32;
} &let {
	firstfrag = pfc_flags & 1;
	lastfrag  = (pfc_flags >> 1) & 1;
	object    = (pfc_flags >> 7) & 1;
} &byteorder = packed_drep.byteorder;

type Syntax = record {
	uuid      : bytestring &length = 16;
	ver_major : uint16;
	ver_minor : uint16;
};

type ContextRequest(ptype: uint8) = record {
	id                : uint16;
	num_syntaxes      : uint8;
	reserved          : padding[1];
	abstract_syntax   : Syntax;
	transfer_syntaxes : Syntax[num_syntaxes];
};

type ContextReply = record {
	ack_result        : uint16;
	ack_reason        : uint16;
	syntax            : Syntax;
};

type ContextList(is_request: bool, ptype: uint8) = record {
	num_contexts   : uint8;
	reserved       : padding[3];
	req_reply      : case is_request of {
		true  -> request_contexts : ContextRequest(ptype)[num_contexts];
		false -> reply_contexts   : ContextReply[num_contexts];
	};
};

type DCE_RPC_Bind = record {
	max_xmit_frag  : uint16;
	max_recv_frag  : uint16;
	assoc_group_id : uint32;
	context_list   : ContextList(true, DCE_RPC_BIND);
};

type DCE_RPC_Bind_Ack = record {
	max_xmit_frag   : uint16;
	max_recv_frag   : uint16;
	assoc_group_id  : uint32;
	sec_addr_length : uint16;
	sec_addr        : bytestring &length=sec_addr_length;
	pad             : padding align 4;
	contexts        : ContextList(false, DCE_RPC_BIND_ACK);
};

type DCE_RPC_Request(h: DCE_RPC_Header) = record {
	alloc_hint   : uint32;
	context_id   : uint16;
	opnum        : uint16;
	has_object   : case h.object of {
		true  -> uuid    : uuid;
		false -> no_uuid : empty;
	};
	stub_pad     : padding align 8;
	stub         : bytestring &restofdata;
};

type DCE_RPC_Response = record {
	alloc_hint   : uint32;
	context_id   : uint16;
	cancel_count : uint8;
	reserved     : uint8;
	stub_pad     : padding align 8;
	stub         : bytestring &restofdata;
};

type DCE_RPC_AlterContext = record {
	max_xmit_frag  : uint16;
	max_recv_frag  : uint16;
	assoc_group_id : uint32;
	context_list   : ContextList(true, DCE_RPC_ALTER_CONTEXT);
};

type DCE_RPC_AlterContext_Resp = record {
	max_xmit_frag   : uint16;
	max_recv_frag   : uint16;
	assoc_group_id  : uint32;
	sec_addr_length : uint16;
	sec_addr        : bytestring &length=sec_addr_length;
	pad             : padding align 4;
	contexts        : ContextList(false, DCE_RPC_ALTER_CONTEXT_RESP);
};

type DCE_RPC_Body(header: DCE_RPC_Header) = case header.PTYPE of {
	DCE_RPC_BIND               -> bind          : DCE_RPC_Bind;
	DCE_RPC_BIND_ACK           -> bind_ack      : DCE_RPC_Bind_Ack;
	DCE_RPC_REQUEST            -> request       : DCE_RPC_Request(header);
	DCE_RPC_RESPONSE           -> response      : DCE_RPC_Response;
	DCE_RPC_ALTER_CONTEXT      -> alter_context : DCE_RPC_AlterContext;
	DCE_RPC_ALTER_CONTEXT_RESP -> alter_resp    : DCE_RPC_AlterContext_Resp;
	default                    -> other         : bytestring &restofdata;
};

type DCE_RPC_Auth_wrapper(header: DCE_RPC_Header) = case header.auth_length of {
	0       -> none : empty;
	default -> auth : DCE_RPC_Auth(header);
};

type DCE_RPC_Auth(header: DCE_RPC_Header) = record {
	type       : uint8;
	level      : uint8;
	pad_len    : uint8;
	reserved   : uint8;
	context_id : uint32;
	blob       : bytestring &length=header.auth_length;
};

flow DCE_RPC_Flow(is_orig: bool) {
	flowunit = DCE_RPC_PDU(is_orig) withcontext(connection, this);

	%member{
		std::map<uint32, std::unique_ptr<FlowBuffer>> fb;
	%}

	# Fragment reassembly.
	function reassemble_fragment(header: DCE_RPC_Header, frag: bytestring): bool
		%{
		auto it = fb.find(${header.call_id});

		if ( ${header.firstfrag} )
			{
			if ( it != fb.end() )
				{
				// We already had a first frag earlier.
				connection()->zeek_analyzer()->Weird("multiple_first_fragments_in_dce_rpc_reassembly");
				connection()->zeek_analyzer()->SetSkip(true);
				return false;
				}

			if ( ${header.lastfrag} )
				{
				// all-in-one packet
				return true;
				}
			else
				{
				// first frag, but not last so we start a flowbuffer
				auto it = fb.emplace(${header.call_id},
				                     std::unique_ptr<FlowBuffer>(new FlowBuffer()));
				auto& flowbuf = it.first->second;
				flowbuf->NewFrame(0, true);
				flowbuf->BufferData(frag.begin(), frag.end());

				if ( fb.size() > zeek::BifConst::DCE_RPC::max_cmd_reassembly )
					{
					connection()->zeek_analyzer()->Weird("too_many_dce_rpc_msgs_in_reassembly");
					connection()->zeek_analyzer()->SetSkip(true);
					}

				if ( flowbuf->data_length() > (int)zeek::BifConst::DCE_RPC::max_frag_data )
					{
					connection()->zeek_analyzer()->Weird("too_much_dce_rpc_fragment_data");
					connection()->zeek_analyzer()->SetSkip(true);
					}

				return false;
				}
			}
		else if ( it != fb.end() )
			{
			// not the first frag, but we have a flow buffer so add to it
			auto& flowbuf = it->second;
			flowbuf->BufferData(frag.begin(), frag.end());

			if ( flowbuf->data_length() > (int)zeek::BifConst::DCE_RPC::max_frag_data )
				{
				connection()->zeek_analyzer()->Weird("too_much_dce_rpc_fragment_data");
				connection()->zeek_analyzer()->SetSkip(true);
				}

			return ${header.lastfrag};
			}
		else
			{
			// no flow buffer and not a first frag, ignore it.
			return false;
			}

		// can't reach here.
		return false;
		%}

	function reassembled_body(h: DCE_RPC_Header, body: bytestring): const_bytestring
		%{
		const_bytestring bd = body;
		auto it = fb.find(${h.call_id});

		if ( it == fb.end() )
			return bd;

		auto& flowbuf = it->second;
		bd = const_bytestring(flowbuf->begin(), flowbuf->end());
		fb.erase(it);

		return bd;
		%}
};
