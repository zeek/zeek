@load ncp
@load app-summary

module NCP_summary;

global ncp_summary_log = open_log_file("ncp-summary") &redef;

type ncp_transaction: record {
	connection_id: conn_id;
	conn_start: time;
	func: string;
	start: time;
	num_req: count;
	req_size: count;
	num_resp: count;
	resp_size: count;
	completion_code: int;	# ... of the first reply
};

global ncp_trans_table: table[conn_id] of ncp_transaction;

function end_ncp_transaction(id: conn_id)
	{
	if ( id !in ncp_trans_table )
		return;

	local t = ncp_trans_table[id];
	print_app_summary(ncp_summary_log, t$connection_id, t$conn_start, t$func, t$start,
		t$num_req, t$req_size,
		t$num_resp, t$resp_size,
		fmt("completion_code %d", t$completion_code));
	}

function new_ncp_transaction(c: connection, func: string): ncp_transaction
	{
	local id = c$id;

	# End any previous trans
	end_ncp_transaction(id);

	local t = [
		$connection_id = id,
		$conn_start = c$start_time,
		$func = func,
		$start = network_time(),
		$num_req = 0, $req_size = 0,
		$num_resp = 0, $resp_size = 0,
		$completion_code = -1];

	ncp_trans_table[id] = t;
	return t;
	}

event ncp_request(c: connection, frame_type: count, length: count, func: count)
	{
	local f = ( frame_type == 0x2222 ) ?
			NCP::ncp_function_name[func] :
			NCP::ncp_frame_type_name[frame_type];

	local t = new_ncp_transaction(c, f);
	++t$num_req;
	t$req_size = t$req_size + length;
	}

event ncp_reply(c: connection, frame_type: count, length: count, req_frame: count, req_func: count, completion_code: count)
	{
	local t = ncp_trans_table[c$id];
	++t$num_resp;
	if ( t$num_resp == 1 )
		t$completion_code = completion_code;
	t$resp_size = t$resp_size + length;
	}

event connection_state_remove(c: connection)
	{
	if ( c$id in ncp_trans_table )
		end_ncp_transaction(c$id);
	}
