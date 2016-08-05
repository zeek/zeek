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
	cxt_attributes:		uint32;
	cxt_uuid:		uuid;
};

type rpc_if_id_t = record {
	if_uuid		: uuid;
	vers_major	: uint16;
	vers_minor	: uint16;
};

type NDR_Format = record {
	intchar		: uint8;
	floatspec	: uint8;
	reserved	: padding[2];
} &let {
	byteorder = (intchar >> 4) ? littleendian : bigendian;
};

#### There might be a endianness problem here: the frag_length
# causes problems despite the NDR_Format having a byteorder set.

type DCE_RPC_Header = record {
	rpc_vers	: uint8 &check(rpc_vers == 5);
	rpc_vers_minor	: uint8;
	PTYPE		: uint8;
	pfc_flags	: uint8;
	packed_drep	: NDR_Format;
	frag_length	: uint16;
	auth_length	: uint16;
	call_id		: uint32;
} &let {
	frag = pfc_flags & 4;
	lastfrag = (! frag) || (pfc_flags & 2);
} &byteorder = packed_drep.byteorder;

type p_context_id_t = uint16;

type p_syntax_id_t = record {
	if_uuid		: uuid;
	if_version	: uint32;
};

type p_cont_elem_t = record {
	p_cont_id	: p_context_id_t;
	n_transfer_syn	: uint8;
	reserved	: padding[1];
	abstract_syntax	: p_syntax_id_t;
	transfer_syntaxes : p_syntax_id_t[n_transfer_syn];
};

type p_cont_list_t = record {
	n_context_elem	: uint8;
	reserved	: padding[3];
	p_cont_elem	: p_cont_elem_t[n_context_elem];
};

type DCE_RPC_Bind = record {
	max_xmit_frag	: uint16;
	max_recv_frag	: uint16;
	assoc_group_id	: uint32;
	p_context_elem	: p_cont_list_t;
};

type DCE_RPC_AlterContext = record {
	max_xmit_frag	: uint16;
	max_recv_frag	: uint16;
	assoc_group_id	: uint32;
	p_context_elem	: p_cont_list_t;
};

type DCE_RPC_Request = record {
	alloc_hint	: uint32;
	p_cont_id	: p_context_id_t;
	opnum		: uint16;
	# object	: uuid;
	# stub_pad_0	: padding align 8;
	stub		: bytestring &restofdata;
};

type DCE_RPC_Response = record {
	alloc_hint	: uint32;
	p_cont_id	: p_context_id_t;
	cancel_count	: uint8;
	reserved	: uint8;
	# stub_pad_0	: padding align 8;
	stub		: bytestring &restofdata;
};

type DCE_RPC_Body(header: DCE_RPC_Header) = case header.PTYPE of {
	DCE_RPC_BIND	 -> bind	: DCE_RPC_Bind;
	DCE_RPC_REQUEST	 -> request	: DCE_RPC_Request;
	DCE_RPC_RESPONSE -> response	: DCE_RPC_Response;
	default		 -> other	: bytestring &restofdata;
};

type DCE_RPC_Auth(header: DCE_RPC_Header) = uint8[header.auth_length];

%include epmapper.pac
