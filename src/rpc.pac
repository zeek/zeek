# $Id:$

# RPCv2. RFC 1831: http://www.ietf.org/rfc/rfc1831.txt

%include binpac.pac
%include bro.pac

analyzer SunRPC withcontext {
	connection:	RPC_Conn;
	flow:		RPC_Flow;
};

enum EnumRPCService {
	RPC_SERVICE_UNKNOWN,
	RPC_SERVICE_PORTMAP,
};

%include rpc-analyzer.pac
%include portmap-analyzer.pac
