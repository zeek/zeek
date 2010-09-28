@load conn-util
@load conn-app-reduced

global conn_size_table: table[conn_id] of count;
global conn_size_log = open_log_file("conn-size") &redef;

function add_to_conn_size(id: conn_id, size: count)
	{
	if ( id !in conn_size_table )
		conn_size_table[id] = 0;
	local previous_size = conn_size_table[id];
	conn_size_table[id] = conn_size_table[id] + size;
	if ( conn_size_table[id] < previous_size )
		{
		print conn_size_log, fmt("ERROR: %.6f size wrapping around: %s, prev_size = %d, add = %d",
			network_time(), conn_id_string(id), previous_size, size);
		}
	}

event after_connections_state_remove(c: connection)
	{
	local id = c$id;
	local app_size: count;
	local transport_size: count;
	if ( id !in conn_size_table )
		conn_size_table[id] = 0;
	app_size = conn_size_table[id];
	transport_size = c$orig$size + c$resp$size;
	local size_delta: int = transport_size - app_size;
	local annotation: string = "none";
	if ( app_size > transport_size )
		annotation = "negative_transport_overhead";
	else if ( size_delta > 1000 && 1.0 * size_delta / transport_size > 0.3 )
		annotation = "suspicious_transport_overhead";

	print conn_size_log, fmt("conn %s app_size %d conn_size %d annotation %s", conn_id_string(id), app_size, transport_size, annotation);

	delete conn_size_table[id];
	}

event connection_state_remove(c: connection)
	{
	event after_connections_state_remove(c);
	}

function print_app_summary(log: file,
		id: conn_id, conn_start: time, func: string, start: time,
		num_req: count, req_size: count, num_resp: count, resp_size: count,
		extra: string)
	{
	add_to_conn_size(id, req_size + resp_size);
	print log, fmt("conn %s conn_start %.6f app %s app_func %s start %.6f req %d pyld_^ %d reply %d pyld_v %d%s",
		conn_id_string(id), conn_start, conn_app[id], func, start,
		num_req, req_size,
		num_resp, resp_size,
		byte_len(extra) > 0 ? cat(" ", extra) : "");
	}
