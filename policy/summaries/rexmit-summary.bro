# Statistical analysis of TCP connection in terms of the packet streams
# in each direction.

@load conn-util

redef capture_filters = { ["tcp"] = "tcp" };
redef ignore_keep_alive_rexmit = T;

global log = open_log_file("rexmit-summary") &redef;

const min_num_pkts = 0;

event conn_stats(c: connection, os: endpoint_stats, rs: endpoint_stats)
	{
	if ( os$num_pkts < min_num_pkts && rs$num_pkts < min_num_pkts )
		return;

	print log, fmt("conn %s start %.6f duration %.6f pkt_^ %d rexmit_pkt_^ %d pyld_^ %d rexmit_pyld_^ %d pkt_v %d rexmit_pkt_v %d pyld_v %d rexmit_pyld_v %d",
		conn_id_string(c$id), c$start_time, c$duration,
		os$num_pkts, os$num_rxmit,
		# os$num_pkts == 0 ? 0.0 : 1.0 * os$num_rxmit / os$num_pkts,
		c$orig$size, os$num_rxmit_bytes,
		rs$num_pkts, rs$num_rxmit,
		# rs$num_pkts == 0 ? 0.0 : 1.0 * rs$num_rxmit / rs$num_pkts,
		c$resp$size, rs$num_rxmit_bytes);
	}
