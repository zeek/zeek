@load conn-util
# @load conn-app
# @load smb-tag
# @load dce-rpc-tag

module ConnSummary;

# redef capture_filters += { ["TUI"] = "tcp or udp or icmp" };
redef capture_filters = { ["ip"] = "ip" };	# to also capture IP fragments
# redef SMB_tag::log_smb_tags = F;
# redef DCE_RPC_tag::log_dce_rpc_tags = F;

global conn_summary_log = open_log_file("conn-summary") &redef;

global conn_annotation: table[conn_id] of string &default = "";

function add_to_conn_annotation(cid: conn_id, new_annotation: string)
	{
	local a: string;
	if ( cid in conn_annotation )
		conn_annotation[cid] =
			cat(conn_annotation[cid], ",", new_annotation);
	else
		conn_annotation[cid] = new_annotation;
	}

# II. Annotation events
event new_connection(c: connection)
	{
	if ( is_tcp_port(c$id$resp_p) )
		{
		if ( c$orig$state != TCP_SYN_SENT )
			{
			# add_to_conn_annotation(c$id, "partial");
			}
		}
	}

event partial_connection(c: connection)
	{
	add_to_conn_annotation(c$id, "partial");
	}

event connection_established(c: connection)
	{
	if ( c$orig$state == TCP_ESTABLISHED && c$resp$state == TCP_ESTABLISHED )
		{
		add_to_conn_annotation(c$id, "established");
		}
	}

event connection_rejected(c: connection)
	{
	add_to_conn_annotation(c$id, "rejected");
	}

event connection_reset(c: connection)
	{
	add_to_conn_annotation(c$id, "reset");
	}

event connection_attempt(c: connection)
	{
	add_to_conn_annotation(c$id, "attempt");
	}

event connection_finished(c: connection)
	{
	add_to_conn_annotation(c$id, "finished");
	}

event icmp_unreachable(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
	add_to_conn_annotation(context$id, "unreach");
	}

event icmp_time_exceeded(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
	add_to_conn_annotation(context$id, "time_exceeded");
	}

event connection_state_remove(c: connection)
	{
	# local tag_smb = get_smb_tag(c$id);
	# local tag_dce_rpc = get_dce_rpc_tag(c$id);

	print conn_summary_log, fmt("conn %s start %.6f duration %.6f app %s pkt_^ %d pyld_^ %d pkt_v %d pyld_v %d state %s notes [%s]",
		conn_id_string(c$id),
		c$start_time,
		c$duration,
		conn_app[c$id],
		c$orig$num_pkts, c$orig$size,
		c$resp$num_pkts, c$resp$size,
		conn_state(c, get_port_transport_proto(c$id$resp_p)),
		conn_annotation[c$id]);

	delete conn_annotation[c$id];
	delete conn_app[c$id];
	}
