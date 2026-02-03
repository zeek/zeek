module NATTraversal;

@load ./natpmp-events

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	## The ports to register for NAT-PMP and PCP.
	const ports = {5351/udp} &redef;

	## Result codes used by nat-traversal.log. Result codes from protocols should be
	## mapped into these.
	type ResultCode: enum {
		SUCCESS = 0,
		PROTOCOL_ERROR = 1,
		POLICY_FAILURE = 2,
		TIMEOUT = 3,
		REREQUEST = 4,
		UNKNOWN = 5,
	};

	## Record type containing the column fields of the NAT Traversal log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the request's connection.
		uid: string &log;
		## The request's connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;
		## Address of host that requested the mapping.
		int_addr: addr &log;
		## Internal port for the mapping.
		int_port: port &log;
		## External port for the mapping.
		ext_port: port &log;
		## The requested lifetime for the mapping.
		lifetime: interval &log;
		## Optional remote host the mapping is tied to. This is used by PCP PEER
		## operations.
		remote_addr: addr &log &optional;
		## Optional remote port the mapping is tied to. This is used by PCP PEER
		## operations.
		remote_port: port &log &optional;
		## Result of the mapping request.
		result: ResultCode &log &optional;
	};

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## Timeout to log requests without a response.
	const request_timeout = 30sec &redef;
}

event zeek_init() &priority=5
	{
	Log::create_stream(NATTraversal::LOG, Log::Stream($columns=Info, $path="nat-traversal",
	    $policy=log_policy));

	Analyzer::register_for_ports(Analyzer::ANALYZER_NATPMP, ports);
	}

type NATPMPConn: record {
	c: connection;
	data: NATPMP::MappingEventData;
};

function natpmp_expire_callback(t: table[port, addr] of NATPMPConn, idx: any) : interval {
	local int_port: port;
	local int_addr: addr;

	[int_port, int_addr] = idx;
	local nc: NATPMPConn = t[int_port, int_addr];

	# request timed out, log it as such.
	Log::write(NATTraversal::LOG, Info(
		$ts = network_time(),
		$uid = nc$c$uid,
		$id = nc$c$id,
		$int_addr = int_addr,
		$int_port = nc$data$int_port,
		$ext_port = nc$data$ext_port,
		$lifetime = nc$data$lifetime,
		$result = TIMEOUT));

	return 0sec;
}

global active_natpmp: table[port, addr] of NATPMPConn &create_expire=request_timeout &expire_func=natpmp_expire_callback;

event NATPMP::natpmp_request(c: connection, data: NATPMP::MappingEventData)
	{
	if ( [data$int_port, c$id$orig_h] in active_natpmp )
		{
		local prev_req: NATPMPConn = active_natpmp[data$int_port, c$id$orig_h];

		# The previous request was never responded to, so consider it a
		# re-request.  We reuse some data from the previous connection so that it
		# maps to the request and not the response.
		#
		# TODO: It might be better to not log these and instead refresh the data
		# in the table.
		Log::write(NATTraversal::LOG, Info(
			$ts = network_time(),
			$uid = prev_req$c$uid,
			$id = prev_req$c$id,
			$int_addr = c$id$orig_h,
			$int_port = data$int_port,
			$ext_port = prev_req$data$ext_port,
			$lifetime = prev_req$data$lifetime,
			$result = REREQUEST));

		delete active_natpmp[data$int_port, c$id$orig_h];
		}

	active_natpmp[data$int_port, c$id$orig_h] = NATPMPConn($c=c, $data=data);
	}

function convert_natpmp_result_code(rc: NATPMP::NATPMP_ResultCode): NATTraversal::ResultCode
	{
	switch(rc)
		{
		case NATPMP::NATPMP_SUCCESS:
			return NATTraversal::SUCCESS;
		case NATPMP::NATPMP_UNSUPPORTED_VERSION: fallthrough;
		case NATPMP::NATPMP_UNSUPPORTED_OPCODE:
			return NATTraversal::PROTOCOL_ERROR;
		case NATPMP::NATPMP_NOT_AUTHORIZED: fallthrough;
		case NATPMP::NATPMP_NETWORK_FAILURE: fallthrough;
		case NATPMP::NATPMP_OUT_OF_RESOURCES:
			return NATTraversal::POLICY_FAILURE;
		}

	return NATTraversal::UNKNOWN;
	}

event NATPMP::natpmp_response(c: connection, data: NATPMP::MappingEventData, result: NATPMP::NATPMP_ResultCode)
	{
	if ( [data$int_port, c$id$orig_h] in active_natpmp )
		{
		# On failures, the response will not have an external port. Pull it out
		# of the original request.
		local req_data: NATPMPConn = active_natpmp[data$int_port, c$id$orig_h];

		Log::write(NATTraversal::LOG, Info(
			$ts = network_time(),
			$uid = req_data$c$uid,
			$id = req_data$c$id,
			$int_addr = c$id$orig_h,
			$int_port = data$int_port,
			$ext_port = req_data$data$ext_port,
			$lifetime = data$lifetime,
			$result = convert_natpmp_result_code(result)));

		delete active_natpmp[data$int_port, c$id$orig_h];
		}
	}

type PCPConn: record {
	c: connection;
	data: NATPMP::PCPEventData;
	is_peer_op: bool;
};

function pcp_expire_callback(t: table[count, count, addr] of PCPConn, idx: any) : interval {
	local nonce_high: count;
	local nonce_low: count;
	local req_host: addr;

	[nonce_high, nonce_low, req_host] = idx;
	local pc: PCPConn = t[nonce_high, nonce_low, req_host];

	local info = Info(
		$ts = network_time(),
		$uid = pc$c$uid,
		$id = pc$c$id,
		$int_addr = pc$data$int_addr,
		$int_port = pc$data$mapping$int_port,
		$ext_port = pc$data$mapping$ext_port,
		$lifetime = pc$data$mapping$lifetime,
		$result = TIMEOUT);

	if ( pc$is_peer_op )
		{
		info$remote_addr = pc$data$remote_addr;
		info$remote_port = pc$data$remote_port;
		}

	Log::write(NATTraversal::LOG, info);

	return 0sec;
}

# The nonce value are not unique across multiple hosts, so this table is keyed off the
# nonce plus the requesting host.
global active_pcp: table[count, count, addr] of PCPConn &create_expire=request_timeout &expire_func=pcp_expire_callback;

function convert_pcp_result_code(rc: NATPMP::PCP_ResultCode): NATTraversal::ResultCode
	{
	switch(rc)
		{
		case NATPMP::PCP_SUCCESS:
			return NATTraversal::SUCCESS;
		case NATPMP::PCP_UNSUPPORTED_VERSION: fallthrough;
		case NATPMP::PCP_MALFORMED_REQUEST: fallthrough;
		case NATPMP::PCP_UNSUPPORTED_OPCODE: fallthrough;
		case NATPMP::PCP_UNSUPPORTED_OPTION: fallthrough;
		case NATPMP::PCP_MALFORMED_OPTION: fallthrough;
		case NATPMP::PCP_UNSUPPORTED_PROTOCOL:
			return NATTraversal::PROTOCOL_ERROR;
		case NATPMP::PCP_NOT_AUTHORIZED: fallthrough;
		case NATPMP::PCP_NETWORK_FAILURE: fallthrough;
		case NATPMP::PCP_NO_RESOURCES: fallthrough;
		case NATPMP::PCP_USER_EX_QUOTA: fallthrough;
		case NATPMP::PCP_CANNOT_PROVIDE_EXTERNAL: fallthrough;
		case NATPMP::PCP_ADDRESS_MISMATCH: fallthrough;
		case NATPMP::PCP_EXCESSIVE_REMOTE_PEERS:
			return NATTraversal::POLICY_FAILURE;
		}

	return NATTraversal::UNKNOWN;
	}

function handle_pcp_request(c: connection, data: NATPMP::PCPEventData, is_peer_op: bool )
	{
	if ( [data$nonce_high, data$nonce_low, c$id$orig_h] in active_pcp )
		{
		local prev_req: PCPConn = active_pcp[data$nonce_high, data$nonce_low, c$id$orig_h];

		# The previous request was never responded to, so consider it a
		# re-request.  We reuse some data from the previous connection so that it
		# maps to the request and not the response.
		#
		# TODO: It might be better to not log these and instead refresh the data
		# in the table.
		local info = Info(
			$ts = network_time(),
			$uid = prev_req$c$uid,
			$id = prev_req$c$id,
			$int_addr = data$int_addr,
			$int_port = data$mapping$int_port,
			$ext_port = prev_req$data$mapping$ext_port,
			$lifetime = prev_req$data$mapping$lifetime,
			$result = REREQUEST);

		if ( is_peer_op )
			{
			info$remote_addr = data$remote_addr;
			info$remote_port = data$remote_port;
			}

		Log::write(NATTraversal::LOG, info);

		delete active_pcp[data$nonce_high, data$nonce_low, c$id$orig_h];
		}

	active_pcp[data$nonce_high, data$nonce_low, c$id$orig_h] = PCPConn($c=c, $data=data, $is_peer_op=is_peer_op);
	}

function handle_pcp_response(c: connection, data: NATPMP::PCPEventData, result: NATPMP::PCP_ResultCode, is_peer_op: bool)
	{
	if ( [data$nonce_high, data$nonce_low, c$id$resp_h] in active_pcp )
		{
		# PCP doesn't have the internal IP data in the responses, so we have to
		# pull it out of the request.
		local req_data: PCPConn = active_pcp[data$nonce_high, data$nonce_low, c$id$resp_h];

		local info = Info(
			$ts = network_time(),
			$uid = req_data$c$uid,
			$id = req_data$c$id,
			$int_addr = req_data$data$int_addr,
			$int_port = data$mapping$int_port,
			$ext_port = data$mapping$ext_port,
			$lifetime = data$mapping$lifetime,
			$result = convert_pcp_result_code(result));

		if ( is_peer_op )
			{
			info$remote_addr = data$remote_addr;
			info$remote_port = data$remote_port;
			}

		Log::write(NATTraversal::LOG, info);

		delete active_pcp[data$nonce_high, data$nonce_low, c$id$resp_h];
		}
	}

event NATPMP::pcp_map_request(c: connection, data: NATPMP::PCPEventData)
	{
	handle_pcp_request(c, data, F);
	}

event NATPMP::pcp_map_response(c: connection, data: NATPMP::PCPEventData, result: NATPMP::PCP_ResultCode)
	{
	handle_pcp_response(c, data, result, F);
	}

event NATPMP::pcp_peer_request(c: connection, data: NATPMP::PCPEventData)
	{
	handle_pcp_request(c, data, T);
	}

event NATPMP::pcp_peer_response(c: connection, data: NATPMP::PCPEventData, result: NATPMP::PCP_ResultCode)
	{
	handle_pcp_response(c, data, result, T);
	}
