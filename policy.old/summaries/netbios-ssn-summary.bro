@load app-summary

redef capture_filters = {
	["netbios-ssn"] = "tcp port 139",
};

module NetbiosSSN_summary;

global netbios_log = open_log_file("netbios-ssn-summary") &redef;

const netbios_msg_types = {
	[0x0]	= "ssn_message",
	[0x81]	= "ssn_request",
	[0x82]	= "positive_resp",
	[0x83]	= "negative_resp",
	[0x84]	= "retarget_resp",
	[0x85]	= "keep_alive",
} &default = function(msg_type: count): string
	{
	return fmt("unknown-0x%x", msg_type);
	};

type netbios_ssn_transaction: record {
	connection_id: conn_id;
	conn_start: time;
	start: time;
	num_req: count;
	req_size: count;
	num_resp: count;
	resp_size: count;
	req_type: string;
	resp_type: string;	# ... of the first reply
	raw_ssn_msg: count;
};

global netbios_ssn_trans_table: table[conn_id] of netbios_ssn_transaction;

function end_netbios_ssn_transaction(id: conn_id)
	{
	if ( id !in netbios_ssn_trans_table )
		return;

	local t = netbios_ssn_trans_table[id];
	print_app_summary(netbios_log, t$connection_id, t$conn_start,
		t$req_type, t$start,
		t$num_req, t$req_size,
		t$num_resp, t$resp_size,
		fmt("req_type %s resp_type %s raw %d",
			t$req_type, t$resp_type, t$raw_ssn_msg));

	delete netbios_ssn_trans_table[id];
	}

function lookup_netbios_ssn_transaction(c: connection, new_trans: bool): netbios_ssn_transaction
	{
	local id = c$id;

	if ( new_trans )
		{
		# End any previous trans
		end_netbios_ssn_transaction(id);
		}

	if ( id !in netbios_ssn_trans_table )
		{
		local t = [
			$connection_id = id,
			$conn_start = c$start_time,
			$start = network_time(),
			$num_req = 0, $req_size = 0,
			$num_resp = 0, $resp_size = 0,
			$req_type = "none", $resp_type = "none",
			$raw_ssn_msg = 0];
		netbios_ssn_trans_table[c$id] = t;
		}

	return netbios_ssn_trans_table[c$id];
	}

event netbios_ssn_message(c: connection, is_orig: bool, msg_type: count, data_len: count)
	{
	local msg_type_name = netbios_msg_types[msg_type];
	local t: netbios_ssn_transaction;
	if ( is_orig )
		{
		t = lookup_netbios_ssn_transaction(c, T);
		++t$num_req;
		if ( t$num_req == 1 )
			t$req_type = msg_type_name;
		t$req_size = t$req_size + data_len;
		}
	else
		{
		t = lookup_netbios_ssn_transaction(c, F);
		++t$num_resp;
		if ( t$num_resp == 1 )
			t$resp_type = msg_type_name;
		t$resp_size = t$resp_size + data_len;
		}
	}

event netbios_session_raw_message(c: connection, is_orig: bool, msg: string)
	{
	local t = lookup_netbios_ssn_transaction(c, F);
	++t$raw_ssn_msg;
	}

event connection_state_remove(c: connection)
	{
	if ( c$id in netbios_ssn_trans_table )
		end_netbios_ssn_transaction(c$id);
	}
