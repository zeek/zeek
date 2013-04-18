%include bro.pac

%extern{
#include "events.bif.h"
%}

analyzer DCE_RPC_Simple withcontext {};

%include dce_rpc-protocol.pac

type DCE_RPC_PDU = record {
	# Set header's byteorder to little-endian (or big-endian) to
	# avoid cyclic dependency.
	header	: DCE_RPC_Header;
	body	: DCE_RPC_Body(header)
		 &length = header.frag_length - sizeof(header) -
				header.auth_length;
	auth	: DCE_RPC_Auth(header);
} &byteorder = header.byteorder,
  &length = header.frag_length;
