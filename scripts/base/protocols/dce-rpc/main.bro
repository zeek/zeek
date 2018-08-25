@load ./consts
@load base/frameworks/dpd

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

	## These are DCE-RPC operations that are ignored, typically due to
	## the operations being noisy and low value on most networks.
	option ignored_operations: table[string] of set[string] = {
		["winreg"] = set("BaseRegCloseKey", "BaseRegGetVersion", "BaseRegOpenKey", "BaseRegQueryValue", "BaseRegDeleteKeyEx", "OpenLocalMachine", "BaseRegEnumKey", "OpenClassesRoot"),
		["spoolss"] = set("RpcSplOpenPrinter", "RpcClosePrinter"),
		["wkssvc"] = set("NetrWkstaGetInfo"),
	};

	type State: record {
		uuid       : string &optional;
		named_pipe : string &optional;
		ctx_to_uuid: table[count] of string &optional;
	};

	# This is to store the log and state information
	# for multiple DCE/RPC bindings over a single TCP connection (named pipes).
	type BackingState: record {
		info: Info;
		state: State;
	};
}

redef DPD::ignore_violations += { Analyzer::ANALYZER_DCE_RPC };

redef record connection += {
	dce_rpc: Info &optional;
	dce_rpc_state: State &optional;
	dce_rpc_backing: table[count] of BackingState &optional;
};

const ports = { 135/tcp };
redef likely_server_ports += { ports };

event bro_init() &priority=5
	{
	Log::create_stream(DCE_RPC::LOG, [$columns=Info, $path="dce_rpc"]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_DCE_RPC, ports);
	}

function normalize_named_pipe_name(pn: string): string
	{
	local parts = split_string(pn, /\\[pP][iI][pP][eE]\\/);
	if ( 1 in parts )
		return to_lower(parts[1]);
	else
		return to_lower(pn);
	}

function set_state(c: connection, state_x: BackingState)
	{
	c$dce_rpc = state_x$info;
	c$dce_rpc_state = state_x$state;

	if ( c$dce_rpc_state?$uuid )
		c$dce_rpc$endpoint = uuid_endpoint_map[c$dce_rpc_state$uuid];
	if ( c$dce_rpc_state?$named_pipe )
		c$dce_rpc$named_pipe = c$dce_rpc_state$named_pipe;
	}

function set_session(c: connection, fid: count)
	{
	if ( ! c?$dce_rpc_backing )
		{
		c$dce_rpc_backing = table();
		}
	if ( fid !in c$dce_rpc_backing )
		{
		local info = Info($ts=network_time(),$id=c$id,$uid=c$uid);
		c$dce_rpc_backing[fid] = BackingState($info=info, $state=State());
		}

	local state_x = c$dce_rpc_backing[fid];
	set_state(c, state_x);
	}

event dce_rpc_bind(c: connection, fid: count, ctx_id: count, uuid: string, ver_major: count, ver_minor: count) &priority=5
	{
	set_session(c, fid);

	local uuid_str = uuid_to_string(uuid);

	if ( ! c$dce_rpc_state?$ctx_to_uuid )
		c$dce_rpc_state$ctx_to_uuid = table();

	c$dce_rpc_state$ctx_to_uuid[ctx_id] = uuid_str;
	c$dce_rpc_state$uuid = uuid_str;
	c$dce_rpc$endpoint = uuid_endpoint_map[uuid_str];
	}

event dce_rpc_alter_context(c: connection, fid: count, ctx_id: count, uuid: string, ver_major: count, ver_minor: count) &priority=5
	{
	set_session(c, fid);

	local uuid_str = uuid_to_string(uuid);

	if ( ! c$dce_rpc_state?$ctx_to_uuid )
		c$dce_rpc_state$ctx_to_uuid = table();

	c$dce_rpc_state$ctx_to_uuid[ctx_id] = uuid_str;
	c$dce_rpc_state$uuid = uuid_str;
	c$dce_rpc$endpoint = uuid_endpoint_map[uuid_str];
	}

event dce_rpc_bind_ack(c: connection, fid: count, sec_addr: string) &priority=5
	{
	set_session(c, fid);

	if ( sec_addr != "" )
		{
		c$dce_rpc_state$named_pipe = sec_addr;
		c$dce_rpc$named_pipe = sec_addr;
		}
	}

event dce_rpc_alter_context_resp(c: connection, fid: count) &priority=5
	{
	set_session(c, fid);
	}

event dce_rpc_request(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count) &priority=5
	{
	set_session(c, fid);

	if ( c?$dce_rpc )
		{
		c$dce_rpc$ts = network_time();
		}
	}

event dce_rpc_response(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count) &priority=5
	{
	set_session(c, fid);

	# In the event that the binding wasn't seen, but the pipe
	# name is known, go ahead and see if we have a pipe name to
	# uuid mapping...
	if ( ! c$dce_rpc?$endpoint && c$dce_rpc?$named_pipe )
		{
		local npn = normalize_named_pipe_name(c$dce_rpc$named_pipe);
		if ( npn in pipe_name_to_common_uuid )
			{
			c$dce_rpc_state$uuid = pipe_name_to_common_uuid[npn];
			}
		}

	if ( c?$dce_rpc )
		{
		if ( c$dce_rpc?$endpoint )
			{
			c$dce_rpc$operation = operations[c$dce_rpc_state$uuid, opnum];
			if ( c$dce_rpc$ts != network_time() )
				c$dce_rpc$rtt = network_time() - c$dce_rpc$ts;
			}

		if ( c$dce_rpc_state?$ctx_to_uuid &&
		     ctx_id in c$dce_rpc_state$ctx_to_uuid )
			{
			local u = c$dce_rpc_state$ctx_to_uuid[ctx_id];
			c$dce_rpc$endpoint = uuid_endpoint_map[u];
			c$dce_rpc$operation = operations[u, opnum];
			}
		}
	}

event dce_rpc_response(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count) &priority=-5
	{
	if ( c?$dce_rpc )
		{
		# If there is no endpoint, there isn't much reason to log.
		# This can happen if the request isn't seen.
		if ( ( c$dce_rpc?$endpoint && c$dce_rpc?$operation ) &&
		     ( c$dce_rpc$endpoint !in ignored_operations
		       ||
		       ( c$dce_rpc?$endpoint && c$dce_rpc?$operation &&
		        c$dce_rpc$operation !in ignored_operations[c$dce_rpc$endpoint] &&
		        "*" !in ignored_operations[c$dce_rpc$endpoint] ) ) )
			{
			Log::write(LOG, c$dce_rpc);
			}
		delete c$dce_rpc;
		}
	}

event connection_state_remove(c: connection)
	{
	if ( ! c?$dce_rpc )
		return;

	# TODO: Go through any remaining dce_rpc requests that haven't been processed with replies.
	for ( i in c$dce_rpc_backing )
		{
		local x = c$dce_rpc_backing[i];
		set_state(c, x);

		# In the event that the binding wasn't seen, but the pipe
		# name is known, go ahead and see if we have a pipe name to
		# uuid mapping...
		if ( ! c$dce_rpc?$endpoint && c$dce_rpc?$named_pipe )
			{
			local npn = normalize_named_pipe_name(c$dce_rpc$named_pipe);
			if ( npn in pipe_name_to_common_uuid )
				{
				c$dce_rpc_state$uuid = pipe_name_to_common_uuid[npn];
				}
			}

		if ( ( c$dce_rpc?$endpoint && c$dce_rpc?$operation ) &&
		     ( c$dce_rpc$endpoint !in ignored_operations
		       ||
		       ( c$dce_rpc?$endpoint && c$dce_rpc?$operation &&
		        c$dce_rpc$operation !in ignored_operations[c$dce_rpc$endpoint] &&
		        "*" !in ignored_operations[c$dce_rpc$endpoint] ) ) )
			{
			Log::write(LOG, c$dce_rpc);
			}
		}
	}
