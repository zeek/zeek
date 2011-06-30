# $Id:$
#
# Netflow data-dumper and proof-of-concept flow restitcher.
# Written by Bernhard Ager (2007).

module NetFlow;

export {
	# Perform flow restitching?
	global netflow_restitch = T &redef;

	# How long to wait for additional flow records after a RST or FIN,
	# so we can compress multiple RST/FINs for the same flow rather than
	# treating them as separate flows.  It's not clear what's the best
	# setting for this timer, but for now we use something larger
	# than the NetFlow inactivity timeout (5 minutes).
	global netflow_finished_conn_expire = 310 sec &redef;
}

global netflow_log = open_log_file("netflow") &redef;

# Should be larger than activity timeout.  Setting only affects table
# declaration, therefore &redef useless.
const netflow_table_expire = 31 min;

type flow: record {
	cnt: count;
	pkts: count;
	octets: count;
	syn: bool;
	fin: bool;
	first: time;
	last: time;
};

function new_flow(r: nf_v5_record): flow
	{
	return [ $cnt = 1,
		 $pkts = r$pkts,
		 $octets = r$octets,
	         $syn = r$tcpflag_syn,
		 $fin = r$tcpflag_fin,
		 $first = r$first,
		 $last = r$last ];
	}

function update_flow(f: flow, r: nf_v5_record)
	{
	f$pkts += r$pkts;
	f$octets += r$octets;
	++f$cnt;
	f$syn = f$syn || r$tcpflag_syn;
	f$fin = f$fin || r$tcpflag_fin;

	if ( r$first < f$first )
		f$first = r$first;
	if ( r$last > f$last )
		f$last = r$last;
	}

function print_flow(t: table[conn_id] of flow, idx: conn_id): interval
	{
	print netflow_log, fmt("%.6f flow %s: %s", network_time(), idx, t[idx]);
	return -1 sec;
	}

event v5flow_finished(t: table[conn_id] of flow, idx: conn_id)
	{
        if ( idx in t )
		{
		print_flow(t, idx);
		delete t[idx];
		}
	}

global flows: table[conn_id] of flow &write_expire = netflow_table_expire
				     &expire_func = print_flow;

event netflow_v5_header(h: nf_v5_header)
	{
	print netflow_log, fmt("%.6f header %s", network_time(), h);
	}

event netflow_v5_record (r: nf_v5_record)
	{
	if ( netflow_restitch )
		{
		if ( r$id in flows )
			update_flow (flows[r$id], r);
		else
			flows[r$id] = new_flow (r);

		if ( r$tcpflag_fin || r$tcpflag_rst )
			schedule netflow_finished_conn_expire {
				v5flow_finished (flows, r$id)
			};
		}

	print netflow_log, fmt("%.6f record %s", network_time(), r);
	}

event bro_done ()
	{
	for ( f_id in flows )
		print_flow(flows, f_id);
	}
