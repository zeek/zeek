@load conn-util
@load dce-rpc
@load app-summary

module DCE_RPC_summary;

global log = open_log_file("dce-rpc-summary") &redef;

type dce_rpc_transaction: record {
	connection_id: conn_id;
	conn_start: time;
	uuid: string;
	opnum: count;
	start: time;
	num_req: count;
	req_size: count;
	num_resp: count;
	resp_size: count;
};

global conn_uuid: table[conn_id] of string &default = DCE_RPC::null_uuid;
global dce_rpc_trans_table: table[conn_id] of dce_rpc_transaction;
# global msg_size: table[conn_id, bool] of count;

function end_dce_rpc_transaction(id: conn_id)
	{
	if ( id !in dce_rpc_trans_table )
		return;

	local t = dce_rpc_trans_table[id];
	local ifname = DCE_RPC::dce_rpc_uuid_name[t$uuid];
	local func_name = DCE_RPC::dce_rpc_func_name[ifname, t$opnum];
	print_app_summary(log,
		t$connection_id,
		t$conn_start,
		fmt("%s/%s", ifname, func_name),
		t$start,
		t$num_req, t$req_size,
		t$num_resp, t$resp_size,
		fmt("ifname %s", ifname));

	delete dce_rpc_trans_table[id];
	}

function new_dce_rpc_transaction(c: connection, uuid: string, opnum: count): dce_rpc_transaction
	{
	local id = c$id;

	# End any previous trans
	end_dce_rpc_transaction(id);

	local t = [
		$connection_id = id, $conn_start = c$start_time,
		$uuid = uuid, $opnum = opnum,
		$start = network_time(),
		$num_req = 0, $req_size = 0,
		$num_resp = 0, $resp_size = 0];

	dce_rpc_trans_table[id] = t;
	return t;
	}

event dce_rpc_message(c: connection, is_orig: bool, ptype: dce_rpc_ptype, msg: string)
	{
	# msg_size[c$id, is_orig] = byte_len(msg);
	}

event dce_rpc_bind(c: connection, uuid: string)
	{
	conn_uuid[c$id] = uuid;
	}

event dce_rpc_request(c: connection, opnum: count, stub: string)
	{
	local t = new_dce_rpc_transaction(c, conn_uuid[c$id], opnum);
	++t$num_req;
	t$req_size = t$req_size + byte_len(stub);
	# t$req_size = t$req_size + msg_size[c$id, T];
	}

event dce_rpc_response(c: connection, opnum: count, stub: string)
	{
	local t = dce_rpc_trans_table[c$id];
	++t$num_resp;
	t$resp_size = t$resp_size + byte_len(stub);
	# t$resp_size = t$resp_size + msg_size[c$id, F];
	}

event connection_state_remove(c: connection)
	{
	if ( c$id in dce_rpc_trans_table )
		end_dce_rpc_transaction(c$id);
	}
