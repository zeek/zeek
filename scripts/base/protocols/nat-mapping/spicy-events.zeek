module NATMapping;

export {
	type EventData: record {
		# Internal port
		int_port: port &log;
		# External port
		ext_port: port &log;
		# Internal IP
		internal_ip: addr &log &optional;
	};

	## Result codes from mapping requests. These are the codes from PCP, which
	## the other protocols map to directly.
	type ResultCode: enum {
		SUCCESS = 0,
		UNSUPP_VERSION = 1,
		NOT_AUTHORIZED = 2,
		MALFORMED_REQUEST = 3,
		UNSUPP_OPCODE = 4,
		UNSUPP_OPTION = 5,
		MALFORMED_OPTION = 6,
		NETWORK_FAILURE = 7,
		NO_RESOURCES = 8,
		UNSUPP_PROTOCOL = 9,
		USER_EX_QUOTA = 10,
		CANNOT_PROVIDE_EXTERNAL = 11,
		ADDRESS_MISMATCH = 12,
		EXCESSIVE_REMOTE_PEERS = 13,
		TIMEOUT = 14,
		REREQUEST = 15,
	};
}

## Generated for NAT mapping requests.
##
## c: The connection.
##
## data: A record for the mapping.
global map_request: event(c: connection, data: EventData);

## Generated for NAT mapping responses.
##
## c: The connection.
##
## data: A record for the mapping.
##
## result: The result of the mapping request.
global map_response: event(c: connection, data: EventData, result: ResultCode);
