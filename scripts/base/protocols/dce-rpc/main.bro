@load ./consts

module DCE_RPC;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp for when the event happened.
		ts         : time     &log;
		## Unique ID for the connection.
		uid        : string   &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id         : conn_id  &log;
		## Round trip time from the request to the response.
		## If either the request or response wasn't seen, 
		## this will be null.
		rtt        : interval &log &optional;

		## Remote pipe name.
		named_pipe : string   &log &optional;
		## Endpoint name looked up from the uuid.
		endpoint   : string   &log &optional;
		## Operation seen in the call.
		operation  : string   &log &optional;
	};

	## Set of interface UUID values to ignore.
	const ignored_uuids: set[string] = set(
		"e1af8308-5d1f-11c9-91a4-08002b14a0fa" #epmapper
	) &redef;
}

redef record Info += {
	uuid: string &optional;
};

redef record connection += {
	dce_rpc: Info &optional;
};

const ports = { 135/tcp };
redef likely_server_ports += { ports };

event bro_init() &priority=5
	{
	Log::create_stream(DCE_RPC::LOG, [$columns=Info, $path="dce_rpc"]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_DCE_RPC, ports);
	}

function set_session(c: connection)
	{
	if ( ! c?$dce_rpc )
		{
		c$dce_rpc = [$ts=network_time(),
		             $id=c$id,
		             $uid=c$uid];
		}
	}

event dce_rpc_bind(c: connection, uuid: string, ver_major: count, ver_minor: count) &priority=5
	{
	set_session(c);

	local uuid_str = uuid_to_string(uuid);
	if ( uuid_str in ignored_uuids )
		return;

	c$dce_rpc$uuid = uuid_str;
	c$dce_rpc$endpoint = uuid_endpoint_map[uuid_str];
	}

event dce_rpc_bind_ack(c: connection, sec_addr: string) &priority=5
	{
	set_session(c);

	if ( sec_addr != "" )
		c$dce_rpc$named_pipe = sec_addr;
	}

event dce_rpc_request(c: connection, opnum: count, stub_len: count) &priority=5
	{
	set_session(c);

	if ( c?$dce_rpc  )
		{
		c$dce_rpc$ts = network_time();
		}
	}

event dce_rpc_response(c: connection, opnum: count, stub_len: count) &priority=5
	{
	set_session(c);

	if ( c?$dce_rpc && c$dce_rpc?$endpoint )
		{
		c$dce_rpc$operation = operations[c$dce_rpc$uuid, opnum];
		if ( c$dce_rpc$ts != network_time() )
			c$dce_rpc$rtt = network_time() - c$dce_rpc$ts;
		}
	}

event dce_rpc_response(c: connection, opnum: count, stub_len: count) &priority=-5
	{
	if ( c?$dce_rpc )
		{
		# If there is not endpoint, there isn't much reason to log.
		# This can happen if the request isn't seen.
		if ( c$dce_rpc?$endpoint )
			Log::write(LOG, c$dce_rpc);
		delete c$dce_rpc;
		}
	}

event connection_state_remove(c: connection)
	{
	if ( ! c?$dce_rpc )
		return;

	# TODO: Go through any remaining dce_rpc requests that haven't been processed with replies.
	}