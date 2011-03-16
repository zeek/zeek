@load app-summary
@load rpc

redef capture_filters += {
	["port-map"] = "port 111",
	["nfs"] = "port 2049",
	# UDP packets are often fragmented
	["nfs-frag"] = "ip[6:2] & 0x1fff != 0",
};

module SUN_RPC_summary;

export {
	global log = open_log_file("sun-rpc-summary") &redef;
}

global nfs_status: table[conn_id] of count;

event nfs_reply_status(n: connection, status: count)
	{
	# print fmt("%.6f status = %d", network_time(), status);
	nfs_status[n$id] = status;
	}

event rpc_call(c: connection, prog: count, ver: count, proc: count, status: count,
		start_time: time, call_len: count, reply_len: count)
	{
	# print fmt("%.6f rpc_call", network_time());
	local prog_name = RPC::program_name(prog);
	local nfs_st = "n/a";
	if ( c$id in nfs_status )
		{
		nfs_st = fmt("%d", nfs_status[c$id]);
		# print fmt("%.6f get_status = %s", network_time(), nfs_st);
		delete nfs_status[c$id];
		}

	print_app_summary(log, c$id, c$start_time,
		fmt("%sv%d/%s",
			prog_name,
			ver,
			RPC::procedure_name(prog, ver, proc)),
		start_time,
		1, call_len, status == RPC_TIMEOUT ? 0 : 1, reply_len,
		fmt("rpc_status %s nfs_status %s", status, nfs_st));
	}
