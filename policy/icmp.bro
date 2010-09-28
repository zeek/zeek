# $Id: icmp.bro 6883 2009-08-19 21:08:09Z vern $

@load hot
@load weird
@load conn
@load scan

global icmp_file = open_log_file("icmp");

redef capture_filters += { ["icmp"] = "icmp" };

module ICMP;

export {

	redef enum Notice += {
		ICMPAsymPayload,	# payload in echo req-resp not the same
		ICMPConnectionPair,	# too many ICMPs between hosts
		ICMPAddressScan,

		# The following isn't presently sufficiently useful due
		# to cold start and packet drops.
		# ICMPUnpairedEchoReply,	# no EchoRequest seen for EchoReply
	};

	# Whether to log detailed information icmp.log.
	const log_details = T &redef;

	# ICMP scan detection.
	const detect_scans = T &redef;
	const scan_threshold = 25 &redef;

	# Analysis of connection pairs.
	const detect_conn_pairs = F &redef;	# switch for connection pair
	const detect_payload_asym = F &redef;	# switch for echo payload
	const conn_pair_threshold = 200 &redef;
}

global conn_pair:table[addr] of set[addr] &create_expire = 1 day;
global conn_pair_thresh_reached: table[addr] of bool &default=F;



type flow_id: record {
	orig_h: addr;
	resp_h: addr;
	id: count;
};

type flow_info: record {
	start_time: time;
	last_time: time;
	orig_bytes: count;
	resp_bytes: count;
	payload: string;
};

const names: table[count] of string = {
	[0] = "echo_reply",
	[3] = "unreach",
	[4] = "quench",
	[5] = "redirect",
	[8] = "echo_req",
	[9] = "router_adv",
	[10] = "router_sol",
	[11] = "time_xcd",
	[12] = "param_prob",
	[13] = "tstamp_req",
	[14] = "tstamp_reply",
	[15] = "info_req",
	[16] = "info_reply",
	[17] = "mask_req",
	[18] = "mask_reply",
} &default = function(n: count): string { return fmt("icmp-%d", n); };


# Map IP protocol number to the protocol's name.
const IP_proto_name: table[count] of string = {
	[1]  = "ICMP",
	[2]  = "IGMP",
	[6]  = "TCP",
	[17] = "UDP",
	[41] = "IPV6",
} &default = function(n: count): string { return fmt("%s", n); }
  &redef;

# Print a report for the given ICMP flow.
function generate_flow_summary(flow: flow_id, fi: flow_info)
	{
	local local_init = is_local_addr(flow$orig_h);
	local local_addr = local_init ? flow$orig_h : flow$resp_h;
	local remote_addr = local_init ? flow$resp_h : flow$orig_h;
	local flags = local_init ? "L" : "";

	local state: string;
	if ( fi$orig_bytes > 0 )
		{
		if ( fi$resp_bytes > 0 )
			state = "SF";
		else
			state = "SH";
		}
	else if ( fi$resp_bytes > 0 )
		state = "SHR";
	else
		state = "OTH";

	print icmp_file, fmt("%.6f %.6f %s %s %s %s %s %s %s",
		fi$start_time, fi$last_time - fi$start_time,
		flow$orig_h, flow$resp_h, "icmp_echo",
		fi$orig_bytes, fi$resp_bytes, state, flags);
	}

# Called when a flow is expired in order to generate a report for it.
function flush_flow(ft: table[flow_id] of flow_info, fi: flow_id): interval
	{
	generate_flow_summary(fi, ft[fi]);
	return 0 sec;
	}

# Table to track each active flow.
global flows: table[flow_id] of flow_info
		&read_expire = 45 sec
		&expire_func = flush_flow;

event icmp_sent(c: connection, icmp: icmp_conn)
	{
	print icmp_file, fmt("%.6f %.6f %s %s %s %s %s %s %s %s %s",
		network_time(), 0.0, icmp$orig_h, icmp$resp_h,
		names[icmp$itype], icmp$itype, icmp$icode, "icmp",
		icmp$len, "0", "SH");
	}

event flow_summary(flow: flow_id, last_time: time)
	{
	if ( flow !in flows )
		return;

	local fi = flows[flow];

	if ( fi$last_time == last_time )
		{
		generate_flow_summary(flow, fi);
		delete flows[flow];
		}
	}

function update_flow(icmp: icmp_conn, id: count, is_orig: bool, payload: string)
	{
	local fid: flow_id;
	fid$orig_h = is_orig ? icmp$orig_h : icmp$resp_h;
	fid$resp_h = is_orig ? icmp$resp_h : icmp$orig_h;
	fid$id = id;

	if ( fid !in flows )
		{
		local info: flow_info;
		info$start_time = network_time();
		info$orig_bytes = info$resp_bytes = 0;
		info$payload = payload;	# checked in icmp_echo_reply
		flows[fid] = info;
		}

	local fi = flows[fid];

	fi$last_time = network_time();

	if ( is_orig )
		fi$orig_bytes = fi$orig_bytes + byte_len(payload);
	else
		fi$resp_bytes = fi$resp_bytes + byte_len(payload);

	schedule +30sec { flow_summary(fid, fi$last_time) };
	}

event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
	{
	update_flow(icmp, id, T, payload);

	local orig = icmp$orig_h;
	local resp = icmp$resp_h;

	# Simple ping scan detector.
	if ( detect_scans &&
	     (orig !in Scan::distinct_peers ||
	      resp !in Scan::distinct_peers[orig]) )
		{
		if ( orig !in Scan::distinct_peers )
			{
			local empty_peer_set: set[addr] &mergeable;
			Scan::distinct_peers[orig] = empty_peer_set;
			}

		if ( resp !in Scan::distinct_peers[orig] )
			add Scan::distinct_peers[orig][resp];

		if ( ! Scan::shut_down_thresh_reached[orig] &&
		     orig !in Scan::skip_scan_sources &&
		     orig !in Scan::skip_scan_nets &&
		     |Scan::distinct_peers[orig]| >= scan_threshold )
			{
			NOTICE([$note=ICMPAddressScan, $src=orig,
				$n=scan_threshold,
				$msg=fmt("%s has icmp echo scanned %s hosts",
				orig, scan_threshold)]);

			Scan::shut_down_thresh_reached[orig] = T;
			}
		}

	if ( detect_conn_pairs )
		{
		if ( orig !in conn_pair )
			{
			local empty_peer_set2: set[addr] &mergeable;
			conn_pair[orig] = empty_peer_set2;
			}

		if ( resp !in conn_pair[orig] )
			add conn_pair[orig][resp];

		if ( ! conn_pair_thresh_reached[orig] &&
		     |conn_pair[orig]| >= conn_pair_threshold )
			{
			NOTICE([$note=ICMPConnectionPair,
				$msg=fmt("ICMP connection threshold exceeded : %s -> %s",
				orig, resp)]);
			conn_pair_thresh_reached[orig] = T;
			}
		}
	}

event icmp_echo_reply(c: connection, icmp: icmp_conn, id: count,
			seq: count, payload: string)
	{
	# Check payload with the associated flow.

	local fid: flow_id;
	fid$orig_h = icmp$resp_h;	# We know the expected results since
	fid$resp_h = icmp$orig_h;	# it's an echo reply.
	fid$id = id;

	if ( fid !in flows )
		{
# 		NOTICE([$note=ICMPUnpairedEchoReply,
# 			$msg=fmt("ICMP echo reply w/o request: %s -> %s",
# 				icmp$orig_h, icmp$resp_h)]);
		}
	else
		{
		if ( detect_payload_asym )
			{
			local fi = flows[fid];
			local pl = fi$payload;

			if ( pl != payload )
				{
				NOTICE([$note=ICMPAsymPayload,
					$msg=fmt("ICMP payload inconsistancy: %s(%s) -> %s(%s)",
					icmp$orig_h, byte_len(fi$payload),
					icmp$resp_h, byte_len(payload))]);
				}
			}
		}

	update_flow(icmp, id, F, payload);
	}

event icmp_unreachable(c: connection, icmp: icmp_conn, code: count,
			context: icmp_context)
	{
	if ( active_connection(context$id) )
		{
		# This section allows Bro to act on ICMP-unreachable packets
		# that happen in the context of an active connection.  It is
		# not currently used.
		local c2 = connection_record(context$id);
		local os = c2$orig$state;
		local rs = c2$resp$state;
		local is_attempt =
			is_tcp_port(c2$id$orig_p) ?
				(os == TCP_SYN_SENT && rs == TCP_INACTIVE) :
				(os == UDP_ACTIVE && rs == UDP_INACTIVE);

		# Insert action here.
		}

	if ( log_details )
		{
		# ICMP unreachable packets are the only ones currently
		# logged.  Due to the connection data contained *within*
		# them, each log line will contain two connections' worth
		# of data.  The initial ICMP connection info is the same
		# as logged for connections.
		print icmp_file, fmt("%.6f %.6f %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s",
			network_time(), 0.0, icmp$orig_h, icmp$resp_h,
			names[icmp$itype], icmp$itype, icmp$icode, "icmp",
			icmp$len, "0", "EncapPkt:",
				# This is the encapsulated packet:
				context$id$orig_h, context$id$orig_p,
				context$id$resp_h, context$id$resp_p,
				context$len, IP_proto_name[context$proto],
				context$len, context$bad_hdr_len,
				context$bad_checksum);
		}
	}
