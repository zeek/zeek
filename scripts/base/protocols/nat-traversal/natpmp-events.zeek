module NATPMP;

@load ./types

export {
	## Data for NAT-PMP events, containing just the fields required for those
	## events. PCP reuses this for some fields.
	type MappingEventData: record {
		## Internal port for the mapping.
		int_port: port;
		## External port for the mapping.
		ext_port: port;
		## Requested lifetime of the mapping.
		lifetime: interval;
		## Epoch time since the NATPMP/PCP server restarted.
		epoch: count;

	};

	## Data for PCP events.
	type PCPEventData: record {
		## Ports and time data for the mapping.
		mapping: MappingEventData;
		## Address of host that requested the mapping. This will be empty in
		## responses.
		int_addr: addr &optional;
		## Address of the external host doing the mapping.
		ext_addr: addr;
		## High bits of nonce used to map requests and responses together.
		nonce_high: count;
		## Low bits of nonce used to map requests and responses together.
		nonce_low: count;
	};

	## Possible result codes sent in NATPMP responses.
	type NATPMP_ResultCode: enum {
		NATPMP_SUCCESS = 0,
		NATPMP_UNSUPPORTED_VERSION = 1,
		NATPMP_NOT_AUTHORIZED = 2,
		NATPMP_NETWORK_FAILURE = 3,
		NATPMP_OUT_OF_RESOURCES = 4,
		NATPMP_UNSUPPORTED_OPCODE = 5,
	};

	## Possible result codes sent in PCP responses.
	type PCP_ResultCode: enum {
		PCP_SUCCESS = 0,
		PCP_UNSUPPORTED_VERSION = 1,
		PCP_NOT_AUTHORIZED = 2,
		PCP_MALFORMED_REQUEST = 3,
		PCP_UNSUPPORTED_OPCODE = 4,
		PCP_UNSUPPORTED_OPTION = 5,
		PCP_MALFORMED_OPTION = 6,
		PCP_NETWORK_FAILURE = 7,
		PCP_NO_RESOURCES = 8,
		PCP_UNSUPPORTED_PROTOCOL = 9,
		PCP_USER_EX_QUOTA = 10,
		PCP_CANNOT_PROVIDE_EXTERNAL = 11,
		PCP_ADDRESS_MISMATCH = 12,
		PCP_EXCESSIVE_REMOTE_PEERS = 13,
	};
}

## Generated for mapping requests over NATPMP.
##
## c: The connection.
##
## data: A record for the mapping.
global natpmp_request: event(c: connection, data: MappingEventData);

## Generated for mapping responses over NATPMP.
##
## c: The connection.
##
## data: A record for the mapping.
##
## result: The result of the mapping request.
global natpmp_response: event(c: connection, data: MappingEventData, result: NATPMP_ResultCode);

## Generated for mapping requests over PCP.
##
## c: The connection.
##
## data: A record for the mapping.
global pcp_map_request: event(c: connection, data: PCPEventData);

## Generated for mapping responses over PCP.
##
## c: The connection.
##
## data: A record for the mapping.
##
## result: The result of the mapping request.
global pcp_map_response: event(c: connection, data: PCPEventData, result: PCP_ResultCode);
