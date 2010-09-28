# $Id:$

# Extends rpc-protocol.pac.

###################
# Hooks into RPC data structures.

refine casefunc RPC_Service += {
	100000	-> RPC_SERVICE_PORTMAP;
};

refine casetype RPC_Params += {
	RPC_SERVICE_PORTMAP	-> portmap:	PortmapParams(call);
};

refine casetype RPC_Results += {
	RPC_SERVICE_PORTMAP	-> portmap:	PortmapResults(call);
};

###################
# Portmap types.

enum PortmapProc {
	PMAPPROC_NULL		= 0,
	PMAPPROC_SET		= 1,
	PMAPPROC_UNSET		= 2,
	PMAPPROC_GETPORT	= 3,
	PMAPPROC_DUMP		= 4,
	PMAPPROC_CALLIT		= 5,
};

type PortmapParams(call: RPC_Call) = case call.proc of {
	PMAPPROC_NULL		-> null:	empty;
	PMAPPROC_SET, PMAPPROC_UNSET, PMAPPROC_GETPORT
				-> mapping:	PortmapMapping;
	PMAPPROC_DUMP		-> dump:	empty;
	PMAPPROC_CALLIT		-> callit:	PortmapCallItParams;
};

type PortmapResults(call: RPC_Call) = case call.proc of {
	PMAPPROC_NULL		-> null:	empty;
	PMAPPROC_SET		-> set:		uint32;
	PMAPPROC_UNSET		-> unset:	uint32;
	PMAPPROC_GETPORT	-> getport:	uint32;
	PMAPPROC_DUMP		-> dump:	PortmapDumpResults;
	PMAPPROC_CALLIT		-> callit:	PortmapCallItResults;
};

type PortmapMapping = record {
	prog:	uint32;
	vers:	uint32;
	proto:	uint32;
	port:	uint32;
};

type PortmapCallItParams = record {
	prog:	uint32;
	vers:	uint32;
	proc:	uint32;
	params:	RPC_Opaque;	# TODO: parse params
};

type PortmapDumpEntry = record {
	cont:		uint32;
	optmapping:	case cont of {
		0 ->		none: empty;
		default ->	mapping: PortmapMapping;
	};
};

type PortmapDumpResults = PortmapDumpEntry[] &until($element.cont != 1);

type PortmapCallItResults = record {
	port:	uint32;
	results: RPC_Opaque;	# TODO: parse results
};
