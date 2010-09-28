# $Id:$

# RPCv2. RFC 1831: http://www.ietf.org/rfc/rfc1831.txt

# This is an analyzer-independent (almost) description of the RPC protocol.

########################################
# Constants.

enum RPC_MsgType {
	RPC_CALL	= 0,
	RPC_REPLY	= 1,
};

enum RPC_ReplyStat {
	MSG_ACCEPTED	= 0,
	MSG_DENIED	= 1,
};

enum RPC_AcceptStat {
	SUCCESS		= 0,
	PROG_UNAVAIL	= 1,
	PROG_MISMATCH	= 2,
	PROC_UNAVAIL	= 3,
	GARBAGE_ARGS	= 4,
	SYSTEM_ERR	= 5,
};

enum RPC_RejectStat {
	RPC_MISMATCH	= 0,
	AUTH_ERROR	= 1,
};

enum RPC_AuthStat {
	AUTH_OK			= 0,

	# failed at remote end
	AUTH_BADCRED		= 1,  # bad credential (seal broken)
	AUTH_REJECTEDCRED	= 2,  # client must begin new session
	AUTH_BADVERF		= 3,  # bad verifier (seal broken)
	AUTH_REJECTEDVERF	= 4,  # verifier expired or replayed
	AUTH_TOOWEAK		= 5,  # rejected for security reasons
	# failed locally
	AUTH_INVALIDRESP	= 6,  # bogus response verifier
	AUTH_FAILED		= 7,  # reason unknown
};


########################################

# To be redef'ed in various protocols.
function RPC_Service(prog: uint32, vers: uint32): EnumRPCService =
	case prog of {
		default -> RPC_SERVICE_UNKNOWN;
	};

# Param "call" might be NULL for RPC_Results, thus "RPC_Service(call)"
# rather than simply "call.service".

%code{

inline EnumRPCService RPC_Service(const RPC_Call* call)
	{
	// If it's an unpaired response, we ignore it for now and
	// complain later in the analyzer.
	return call ? call->service() : RPC_SERVICE_UNKNOWN;
	}
%}


########################################
# Data structures.

# Export the source data for each RPC_Message for RPC retransmission checking.
# With &exportsourcedata, "sourcedata" are defined as members of
# class RPC_Message.

type RPC_Message = record {
	xid:		uint32;
	msg_type:	uint32;
	msg_body:	case msg_type of {
		RPC_CALL	-> call:	RPC_Call(this);
		RPC_REPLY	-> reply:	RPC_Reply(this);
	} &requires(length);
} &let {
	length = sourcedata.length();	# length of the RPC_Message
} &byteorder = bigendian, &exportsourcedata, &refcount;

type RPC_Call(msg: RPC_Message) = record {
	rpcvers:	uint32;
	prog:		uint32;
	vers:		uint32;
	proc:		uint32;
	cred:		RPC_OpaqueAuth;
	verf:		RPC_OpaqueAuth;

	# Compute 'service' before parsing params.
	params:		RPC_Params(this) &requires(service);
} &let {
	service: EnumRPCService = RPC_Service(prog, vers);

	# Copy the source data for retransmission checking.
	msg_source_data: bytestring = msg.sourcedata;

	# Register the RPC call by the xid.
	newcall: bool = context.connection.NewCall(msg.xid, this)
		&requires(msg_source_data);
};

type RPC_Reply(msg: RPC_Message) = record {
	# Find the corresponding RPC call.
	# Further parsing of reply depends on call.{prog, vers, proc}
	stat:		uint32;
	reply:		case stat of {
		MSG_ACCEPTED	-> areply:	RPC_AcceptedReply(call);
		MSG_DENIED	-> rreply:	RPC_RejectedReply(call);
	} &requires(call);
} &let {
	call: RPC_Call = context.connection.FindCall(msg.xid);
	success: bool = (stat == MSG_ACCEPTED && areply.stat == SUCCESS);
};

type RPC_AcceptedReply(call: RPC_Call) = record {
	verf:		RPC_OpaqueAuth;
	stat:		uint32;
	data:		case stat of {
		SUCCESS		-> results:	RPC_Results(call);
		PROG_MISMATCH	-> mismatch:	RPC_MismatchInfo;
		default		-> other:	empty;
	};
};

type RPC_RejectedReply(call: RPC_Call) = record {
	stat:		uint32;
	data:		case stat of {
		RPC_MISMATCH	-> mismatch:	RPC_MismatchInfo;
		AUTH_ERROR	-> auth_stat:	uint32;	# RPC_AuthStat
	};
};

type RPC_MismatchInfo = record {
	hi:	uint32;
	low:	uint32;
};

type RPC_Opaque = record {
	length:	uint32;
	data:	uint8[length];
	pad:	padding align 4;	# pad to 4-byte boundary
};

type RPC_OpaqueAuth = record {
	flavor: uint32;
	opaque: RPC_Opaque;
};

# To be extended by higher level protocol analyzers. See portmap-protocol.pac.
type RPC_Params(call: RPC_Call) = case RPC_Service(call) of {
	default			-> stub: uint8[] &restofdata;
};

type RPC_Results(call: RPC_Call) = case RPC_Service(call) of {
	default		-> stub: uint8[] &restofdata;
};
