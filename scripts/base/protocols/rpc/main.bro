
#
# Log RPC request and reply messages. Does not in itself start/activate 
# an analyzer. You need to load portmap and/or NFS for that
#
# TODO: maybe automatically load portmap, add a generic RPC analyzer and 
# use expect connection, so that we can see RPC request/replies for RPC
# programs for which we don't have an analyzer. 
#

@load base/utils/conn-ids

module RPC;

export {
	global log_file = open_log_file("rpc") &redef;
	# whether to match request to replies on the policy layer. 
	# (will report on rexmit and missing requests or replies)
	global track_requests_replies = T &redef; 
}


type rpc_call_state: enum {
	NONE,
	HAVE_CALL,
	HAVE_REPLY
};

type rpc_call_info: record {
	state: rpc_call_state;
	calltime: time;
	cid: conn_id;
};

function new_call(cid: conn_id): rpc_call_info 
	{
	local ci: rpc_call_info;

	ci$state = NONE;
	ci$calltime = network_time();
	ci$cid = cid;
	return ci;
	}

function rpc_expire_xid(t: table[count] of rpc_call_info, xid: count): interval 
	{
	local ci = t[xid];
	if (ci$state != HAVE_REPLY)
		print log_file, fmt("%.6f %s %s note XID %d never recevied a reply", 
				  ci$calltime, id_string(ci$cid),
				   get_port_transport_proto(ci$cid$orig_p), xid);
	return 0 sec;
	}

function new_xid_table(): table[count] of rpc_call_info 
	{
	local inner: table[count] of rpc_call_info  &write_expire=rpc_timeout &expire_func=rpc_expire_xid;
	return inner;
	}


# Match requests to replies. 
# The analyzer does this indepently and might differ in timeouts and 
# handling of xid reuse. 
# FIXME: add timeouts. Note, we do clean up on connection_state_remove
global rpc_calls: table[conn_id] of table[count] of rpc_call_info;
#	&write_expire = rpc_timeout &expire_func=expire_rpc_call;

 
event rpc_dialogue(c: connection, prog: count, ver: count, proc: count, status: rpc_status, start_time: time, call_len: count, reply_len: count) 
	{
	# TODO: We currently do nothing here.
	# using the rpc_call and rpc_reply events, is all we need.
	}

event rpc_call(c: connection, xid: count, prog: count, ver: count, proc: count, call_len: count)
	{
	if (track_requests_replies) 
		{
		if (c$id !in rpc_calls)
			rpc_calls[c$id] = new_xid_table();
		if (xid !in rpc_calls[c$id]) 
			rpc_calls[c$id][xid] = new_call(c$id);
		local curstate = rpc_calls[c$id][xid]$state;

		if (curstate == HAVE_CALL)
			print log_file, fmt("%.6f %s %s note XID %d call retransmitted", 
					  network_time(), id_string(c$id), get_port_transport_proto(c$id$orig_p),
					  xid);
		else if (curstate == HAVE_REPLY)
			print log_file, fmt("%.6f %s %s note XID %d call received after reply", 
					  network_time(), id_string(c$id), get_port_transport_proto(c$id$orig_p),
					  xid);
		rpc_calls[c$id][xid]$state = HAVE_CALL;
		}

	print log_file, fmt("%.6f %s %s rpc_call %d %d %d %d %d", 
		network_time(), id_string(c$id), get_port_transport_proto(c$id$orig_p),
		xid, prog, ver, proc, call_len);
	}

event rpc_reply(c: connection, xid: count, status: rpc_status, reply_len: count) 
	{
	if (track_requests_replies) 
		{
		if (c$id !in rpc_calls)
			rpc_calls[c$id] = new_xid_table();
		if (xid !in rpc_calls[c$id])
			{
			rpc_calls[c$id][xid] = new_call(c$id);
			# XXX: what to do about calltime in rpc_call_info??
			}
		if (rpc_calls[c$id][xid]$state == NONE) 
			print log_file, fmt("%.6f %s %s note XID %d reply but call is missing", 
					  network_time(), id_string(c$id), get_port_transport_proto(c$id$orig_p),
					  xid);
		else if (rpc_calls[c$id][xid]$state == HAVE_REPLY)
			print log_file, fmt("%.6f %s %s note XID %d reply retransmitted", 
					  network_time(), id_string(c$id), get_port_transport_proto(c$id$orig_p),
					  xid);
		rpc_calls[c$id][xid]$state = HAVE_REPLY;
		}

	print log_file, fmt("%.6f %s %s rpc_reply %d %s %d", 
		network_time(), reverse_id_string(c$id), get_port_transport_proto(c$id$orig_p),
		xid, status, reply_len);
	}



function finish_calls(cid:  conn_id)
	{
	for (xid in rpc_calls[cid]) 
		rpc_expire_xid(rpc_calls[cid], xid);
	}

event connection_state_remove(c: connection)
	{
	if (c$id !in rpc_calls)
		return;
	finish_calls(c$id);
	delete rpc_calls[c$id];
	}

event bro_done() 
	{
	for (cid in rpc_calls)
		finish_calls(cid);
	}
