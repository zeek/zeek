# Statistical analysis of TCP connection in terms of the packet streams
# in each direction.

@load dns-lookup
@load udp


event conn_stats(c: connection, os: endpoint_stats, rs: endpoint_stats)
	{
	local id = c$id;

	print fmt("%.6f %s %s %s %s %s %s %s %s %s",
		c$start_time, c$duration, id$orig_p, id$resp_p,
		conn_size(c$orig, tcp), conn_size(c$resp, tcp),
		id$orig_h, id$resp_h, os, rs);
	}
