@load base/frameworks/notice

module PacketFilter;

export {
	const max_bpf_shunts = 100 &redef;

	global shunt_conn: function(id: conn_id): bool;
	
	redef enum Notice::Type += {
		## Indicative that :bro:id:`max_bpf_shunts` connections are already
		## being shunted with BPF filters and no more are allowed.
		No_More_Conn_Shunts_Available,
	};
}

global shunted_conns: set[conn_id];
global shunted_conns_non_flag_tracking: set[conn_id];

function conn_shunt_filters()
	{
	# TODO: this could wrongly match if a connection happens with the ports reversed.
	local filter = "";
	local ipv4_tcp_filter = "";
	for ( id in shunted_conns )
		{
		local prot = get_port_transport_proto(id$resp_p);
		
		# TODO: add ipv6
		#if ( prot == udp ) #|| is_ipv6_addr(id$orig_h) )
		#	{
		#	next;
		#	shunt_for()
		#	}
		
		if ( prot == tcp )
			ipv4_tcp_filter = combine_filters(ipv4_tcp_filter, "and", fmt("host %s and port %d and host %s and port %d and %s", id$orig_h, id$orig_p, id$resp_h, id$resp_p, prot));
		}
	
	ipv4_tcp_filter = combine_filters(ipv4_tcp_filter, "and", "tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) == 0");

	if ( ipv4_tcp_filter == "" )
		return;
	PacketFilter::exclude("conn_shunt_filters", ipv4_tcp_filter);
	}

event bro_init() &priority=5
	{
	register_filter_factory([
		$func()={ return conn_shunt_filters(); }
		]);
	}

function shunt_conn(id: conn_id): bool
	{
	if ( |shunted_conns| + |shunted_conns_non_flag_tracking| > max_bpf_shunts )
		{
		NOTICE([$note=No_More_Conn_Shunts_Available,
		        $msg=fmt("%d BPF shunts are in place and no more will be added until space clears.", max_bpf_shunts)]);
		return F;
		}
	
	add shunted_conns[id];
	install();
	return T;
	}
	
event connection_state_remove(c: connection) &priority=-5
	{
	# Don't rebuild the filter right away because the packet filter framework will check every few minutes
	# and update the filter if things have changed.
	if ( c$id in shunted_conns )
		delete shunted_conns[c$id];
	}