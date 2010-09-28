# $Id:$
#
# bittorrent.bro - policy script for analyzing BitTorrent traffic
# ---------------------------------------------------------------
# This code contributed by Nadi Sarrar.

@load dpd
@load weird

module BitTorrent;

export {
	# Whether to log the length of PDUs.
	global log_pdu_length = T &redef;
}

redef capture_filters += { ["bittorrent"] = "tcp" };

type bt_peer_state: enum {
	choked,	# peer won't receive any responses to requests (initial state)
	unchoked	# peer may do requests
};

type bt_peer_info: record {
	# Total of pure peer wire protocol overhead data (w/o pieces).
	protocol_total: count &default = 0;

	# State of the peer - choked or unchoked.
	state: bt_peer_state &default = choked;

	# Total number of seconds the peer was unchoked.
	unchoked: interval &default = 0 secs;

	# Time of the last received unchoke message.
	time_last_unchoked: time;
};

type bt_peer_conn: record {
	id: count;
	orig: bt_peer_info;
	resp: bt_peer_info;
	weird: bool &default = F;
};

global bittorrent_log = open_log_file("bittorrent") &redef;
global bt_peer_conns : table[conn_id] of bt_peer_conn;
global peer_conn_count = 0;

function record_peer_protocol_traffic(c: connection, is_orig: bool,
					protocol_len: count): count
	{
	if ( c$id in bt_peer_conns )
		{
		local pc = bt_peer_conns[c$id];

		if ( is_orig )
			pc$orig$protocol_total += protocol_len;
		else
			pc$resp$protocol_total += protocol_len;

		return pc$id;
		}

	return 0;
	}

function record_choke(pi: bt_peer_info, now: time)
	{
	if ( pi$state == unchoked )
		{
		pi$state = choked;
		pi$unchoked += now - pi$time_last_unchoked;
		}
	}

function record_unchoke(pi: bt_peer_info, now: time)
	{
	if ( pi$state == choked )
		{
		pi$state = unchoked;
		pi$time_last_unchoked = now;
		}
	}

function lookup_bt_peer(id: conn_id): bt_peer_conn
	{
	if ( id in bt_peer_conns )
		return bt_peer_conns[id];

	local orig: bt_peer_info;
	local resp: bt_peer_info;
	local pc: bt_peer_conn;
	pc$orig = orig;
	pc$resp = resp;
	pc$id = ++peer_conn_count;
	bt_peer_conns[id] = pc;

	return pc;
	}

function bt_log_id(id: conn_id, cid: count, tag: string, is_orig: bool): string
	{
	return fmt("%.6f P%d %s %s:%d %s %s:%d",
			network_time(), cid, tag, id$orig_h, id$orig_p,
			is_orig ? ">" : "<", id$resp_h, id$resp_p);
	}

function pdu_log_len(len: count): string
	{
	return log_pdu_length ? fmt("[PDU-len:%d]", len) : "";
	}

function log_pdu(c: connection, is_orig: bool, tag: string, len: count): count
	{
	local cid = record_peer_protocol_traffic(c, is_orig, len);
	print bittorrent_log,
		fmt("%s %s", bt_log_id(c$id, cid, tag, is_orig),
				pdu_log_len(len));

	return cid;
	}

function log_pdu_str(c: connection, is_orig: bool, tag: string, len: count,
			str: string)
	{
	local cid = record_peer_protocol_traffic(c, is_orig, len);
	print bittorrent_log,
		fmt("%s %s %s", bt_log_id(c$id, cid, tag, is_orig),
				pdu_log_len(len), str);
	}

function log_pdu_str_n(c: connection, is_orig: bool, tag: string, len: count,
			n: count, str: string)
	{
	local cid = record_peer_protocol_traffic(c, is_orig, len);
	print bittorrent_log,
		fmt("%s %s %s", bt_log_id(c$id, cid, tag, is_orig),
			pdu_log_len(n), str);
	}

event bittorrent_peer_handshake(c: connection, is_orig: bool, reserved: string,
				info_hash: string, peer_id: string)
	{
	local pc = lookup_bt_peer(c$id);
	log_pdu_str(c, is_orig, "handshake", 68,
		fmt("[peer_id:%s info_hash:%s reserved:%s]",
			bytestring_to_hexstr(peer_id),
			bytestring_to_hexstr(info_hash),
			bytestring_to_hexstr(reserved)));
	}

event bittorrent_peer_keep_alive(c: connection, is_orig: bool)
	{
	log_pdu(c, is_orig, "keep-alive", 4);
	}

event bittorrent_peer_choke(c: connection, is_orig: bool)
	{
	local cid = log_pdu(c, is_orig, "choke", 5);
	if ( cid > 0 )
		{
		local pc = bt_peer_conns[c$id];
		record_choke(is_orig ? pc$resp : pc$orig, network_time());
		}
	}

event bittorrent_peer_unchoke(c: connection, is_orig: bool)
	{
	local cid = log_pdu(c, is_orig, "unchoke", 5);
	if ( cid > 0 )
		{
		local pc = bt_peer_conns[c$id];
		record_unchoke(is_orig ? pc$resp : pc$orig, network_time());
		}
	}

event bittorrent_peer_interested(c: connection, is_orig: bool)
	{
	log_pdu(c, is_orig, "interested", 5);
	}

event bittorrent_peer_not_interested(c: connection, is_orig: bool)
	{
	log_pdu(c, is_orig, "not-interested", 5);
	}

event bittorrent_peer_have(c: connection, is_orig: bool, piece_index: count)
	{
	log_pdu(c, is_orig, "have", 9);
	}

event bittorrent_peer_bitfield(c: connection, is_orig: bool, bitfield: string)
	{
	log_pdu_str(c, is_orig, "bitfield", 5 + byte_len(bitfield), 
			fmt("[bitfield:%s]",
				bytestring_to_hexstr(bitfield)));
	}

event bittorrent_peer_request(c: connection, is_orig: bool, index: count,
				begin: count, length: count)
	{
	log_pdu_str(c, is_orig, "request", 17,
		fmt("[index:%d begin:%d length:%d]", index, begin, length));
	}

event bittorrent_peer_piece(c: connection, is_orig: bool, index: count,
				begin: count, piece_length: count)
	{
	log_pdu_str_n(c, is_orig, "piece", 13, 13 + piece_length,
		fmt("[index:%d begin:%d piece_length:%d]",
			index, begin, piece_length));
	}

event bittorrent_peer_cancel(c: connection, is_orig: bool, index: count,
				begin: count, length: count)
	{
	log_pdu_str(c, is_orig, "cancel", 7,
		fmt("[index:%d begin:%d length:%d]",
			index, begin, length));
	}

event bittorrent_peer_port(c: connection, is_orig: bool, listen_port: port)
	{
	log_pdu_str(c, is_orig, "port", 5,
			fmt("[listen_port:%s]", listen_port));
	}

event bittorrent_peer_unknown(c: connection, is_orig: bool, message_id: count,
				data: string)
	{
	log_pdu_str(c, is_orig, "<unknown>", 5 + byte_len(data),
			fmt("[message_id:%d]", message_id));
	}

event bittorrent_peer_weird(c: connection, is_orig: bool, msg: string)
	{
	local pc = lookup_bt_peer(c$id);
	pc$weird = T;

	print bittorrent_log,
		fmt("%s [%s]", bt_log_id(c$id, pc$id, "<weird>", is_orig), msg);

	event conn_weird(msg, c);
	}

function log_close(c: connection, pc: bt_peer_conn, is_orig: bool)
	{
	local endp = is_orig ? c$orig : c$resp;
	local peer_i = is_orig ? pc$orig : pc$resp;

	local status =
		pc$weird ?
			fmt("size:%d", endp$size) :
			fmt("unchoked:%.06f size_protocol:%d size_pieces:%d",
				peer_i$unchoked, peer_i$protocol_total,
				endp$size - peer_i$protocol_total);

	print bittorrent_log,
		fmt("%s [duration:%.06f %s]",
			bt_log_id(c$id, pc$id, "<closed>", is_orig),
			c$duration, status);
	}

event connection_state_remove(c: connection)
	{
	if ( c$id !in bt_peer_conns )
		return;

	local pc = bt_peer_conns[c$id];
	delete bt_peer_conns[c$id];

	record_choke(pc$orig, c$start_time + c$duration);
	record_choke(pc$resp, c$start_time + c$duration);

	log_close(c, pc, T);
	log_close(c, pc, F);
	}
