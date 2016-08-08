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
	DCE_RPC_SHUTDOWN,
	DCE_RPC_CO_CANCEL,
	DCE_RPC_ORPHANED,
};

type uuid = bytestring &length = 16;

type context_handle = record {
	attrs : uint32;
	uuid  : bytestring &length = 16;
};

type DCE_RPC_PDU(is_orig: bool) = record {
	# Set header's byteorder to little-endian (or big-endian) to
	# avoid cyclic dependency.
	header  : DCE_RPC_Header(is_orig);
	# TODO: bring back reassembly.  It was having trouble.
	#frag    : bytestring &length = body_length;
	body    : DCE_RPC_Body(header);
	auth    : DCE_RPC_Auth_wrapper(header);
} &let {
	#body_length      : int  = header.frag_length - sizeof(header) - header.auth_length;
	#frag_reassembled : bool = $context.flow.reassemble_fragment(frag, header.lastfrag);
	#body             : DCE_RPC_Body(header)
	#	withinput $context.flow.reassembled_body()
	#	&if frag_reassembled;
} &byteorder = header.byteorder, &length = header.frag_length;

type NDR_Format = record {
	intchar    : uint8;
	floatspec  : uint8;
	reserved   : padding[2];
} &let {
	byteorder = (intchar >> 4) ? littleendian : bigendian;
};

# There might be a endianness problem here: the frag_length
# causes problems despite the NDR_Format having a byteorder set.

type DCE_RPC_Header(is_orig: bool) = record {
	rpc_vers       : uint8 &check(rpc_vers == 5);
	rpc_vers_minor : uint8;
	PTYPE          : uint8;
	pfc_flags      : uint8;
	packed_drep    : NDR_Format;
	frag_length    : uint16;
	auth_length    : uint16;
	call_id        : uint32;
} &let {
	frag = pfc_flags & 4;
	lastfrag = (! frag) || (pfc_flags & 2);
} &byteorder = packed_drep.byteorder;

type Syntax = record {
	uuid      : bytestring &length = 16;
	ver_major : uint16;
	ver_minor : uint16;
};

type ContextRequest = record {
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

type ContextList(is_request: bool) = record {
	num_contexts   : uint8;
	reserved       : padding[3];
	req_reply      : case is_request of {
		true  -> request_contexts : ContextRequest[num_contexts];
		false -> reply_contexts   : ContextReply[num_contexts];
	};
};

type DCE_RPC_Bind = record {
	max_xmit_frag  : uint16;
	max_recv_frag  : uint16;
	assoc_group_id : uint32;
	context_list   : ContextList(1);
};

type DCE_RPC_Bind_Ack = record {
	max_xmit_frag   : uint16;
	max_recv_frag   : uint16;
	assoc_group_id  : uint32;
	sec_addr_length : uint16;
	sec_addr        : bytestring &length=sec_addr_length;
	pad             : padding align 4;
	contexts        : ContextList(0);
};

type DCE_RPC_Request = record {
	alloc_hint   : uint32;
	context_id   : uint16;
	opnum        : uint16;
	# object     : uuid;
	# stub_pad_0 : padding align 8;
	stub         : bytestring &restofdata;
};

type DCE_RPC_Response = record {
	alloc_hint   : uint32;
	context_id   : uint16;
	cancel_count : uint8;
	reserved     : uint8;
	# stub_pad_0 : padding align 8;
	stub         : bytestring &restofdata;
};

type DCE_RPC_AlterContext = record {
	max_xmit_frag  : uint16;
	max_recv_frag  : uint16;
	assoc_group_id : uint32;
	contexts       : ContextList(0);
};

type DCE_RPC_AlterContext_Resp = record {
	max_xmit_frag  : uint16;
	max_recv_frag  : uint16;
	assoc_group_id : uint32;
	sec_addr_len   : uint16;
	contexts       : ContextList(0);
};

type DCE_RPC_Body(header: DCE_RPC_Header) = case header.PTYPE of {
	DCE_RPC_BIND               -> bind          : DCE_RPC_Bind;
	DCE_RPC_BIND_ACK           -> bind_ack      : DCE_RPC_Bind_Ack;
	DCE_RPC_REQUEST            -> request       : DCE_RPC_Request;
	DCE_RPC_RESPONSE           -> response      : DCE_RPC_Response;
	# TODO: Something about the two following structures isn't being handled correctly.
	#DCE_RPC_ALTER_CONTEXT      -> alter_context : DCE_RPC_AlterContext;
	#DCE_RPC_ALTER_CONTEXT_RESP -> alter_resp    : DCE_RPC_AlterContext_Resp;
	default                    -> other         : bytestring &restofdata;
} &length=header.frag_length - 16 - header.auth_length - (header.auth_length==0 ? 0 : 8);

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
