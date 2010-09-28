# $Id:$
#
# bt-tracker.bro - analysis of BitTorrent tracker traffic
# ------------------------------------------------------------------------------
# This code contributed by Nadi Sarrar.

@load dpd
@load weird

module BitTorrent;

export {
	# Whether to log tracker URIs.
	global log_tracker_request_uri = F &redef;
}

redef capture_filters += { ["bittorrent"] = "tcp", };

global bt_tracker_log = open_log_file("bt-tracker") &redef;

global bt_tracker_conns: table[conn_id] of count;
global tracker_conn_count: count = 0;


function bt_log_tag(id: conn_id, cid: count, tag: string, is_orig: bool): string
	{
	return fmt("%.6f T%d %s %s:%d %s %s:%d",
			 network_time(), cid, tag, id$orig_h, id$orig_p,
			 is_orig ? ">" : "<", id$resp_h, id$resp_p);
	}

event bt_tracker_request(c: connection, uri: string,
				headers: bt_tracker_headers)
	{
	# Parse and validate URI.
	local pair = split1(uri, /\?/);
	local keys = split(pair[2], /&/);

	local info_hash = "";
	local peer_ide = "";
	local peer_port = 0/udp;
	local uploaded = -1;
	local downloaded = -1;
	local left = -1;
	local compact = T;
	local peer_event = "empty";

	for ( idx in keys )
		{
		local keyval = split1(keys[idx], /=/);
		if ( length(keyval) != 2 )
			next;

		local key = to_lower(keyval[1]);
		local val = keyval[2];

		if ( key == "info_hash" )
			info_hash = unescape_URI(val);
		else if ( key == "peer_id" )
			peer_ide = unescape_URI(val);
		else if ( key == "port" )
			peer_port = to_port(to_count(val), tcp);
		else if ( key == "uploaded" )
			uploaded = to_int(val);
		else if ( key == "downloaded" )
			downloaded = to_int(val);
		else if ( key == "left" )
			left = to_int(val);
		else if ( key == "compact" )
			compact = (to_int(val) == 1);

		else if ( key == "event" )
			{
			val = to_lower(val);
			if ( val == /started|stopped|completed/ )
				peer_event = val;
			}
		}

	if ( info_hash == "" || peer_ide == "" || peer_port == 0/udp )
		{ # Does not look like BitTorrent.
		disable_analyzer(c$id, current_analyzer());
		delete bt_tracker_conns[c$id];
		return;
		}

	if ( peer_port != 0/tcp )
		expect_connection(to_addr("0.0.0.0"), c$id$orig_h,
					peer_port, ANALYZER_BITTORRENT, 1 min);

	local id: count;
	if ( c$id in bt_tracker_conns )
		id = bt_tracker_conns[c$id];
	else
		{
		id = ++tracker_conn_count;
		bt_tracker_conns[c$id] = id;
		}

	print bt_tracker_log,
		fmt("%s [peer_id:%s info_hash:%s port:%s event:%s up:%d down:%d left:%d compact:%s]%s",
			bt_log_tag(c$id, id, "request", T),
			bytestring_to_hexstr(peer_ide),
			bytestring_to_hexstr(info_hash),
			peer_port, peer_event,
			uploaded, downloaded, left,
			compact ? "yes" : "no",
			log_tracker_request_uri ? fmt(" GET %s", uri) : "");
	}

function benc_status(benc: bittorrent_benc_dir, tag: string): string
	{
	if ( tag !in benc || ! benc[tag]?$i )
		return "";

	local fmt_tag = sub(tag, / /, "_");
	return fmt("%s:%d", fmt_tag, benc[tag]$i);
	}

event bt_tracker_response(c: connection, status: count,
				headers: bt_tracker_headers,
				peers: bittorrent_peer_set,
				benc: bittorrent_benc_dir)
	{
	if ( c$id !in bt_tracker_conns )
		return;

	local id = bt_tracker_conns[c$id];

	for ( peer in peers )
		expect_connection(c$id$orig_h, peer$h, peer$p,
					ANALYZER_BITTORRENT, 1 min);

	if ( "failure reason" in benc )
		{
		print bt_tracker_log,
			fmt("%s [failure_reason:\"%s\"]",
				bt_log_tag(c$id, id, "response", F),
				benc["failure reason"]?$s ?
					benc["failure reason"]$s : "");
		return;
		}

	print bt_tracker_log,
		fmt("%s [%s%s%s%s%speers:%d]",
			bt_log_tag(c$id, id, "response", F),
			benc_status(benc, "warning message"),
			benc_status(benc, "complete"),
			benc_status(benc, "incomplete"),
			benc_status(benc, "interval"),
			benc_status(benc, "min interval"),
			length(peers));
	}

event bt_tracker_response_not_ok(c: connection, status: count,
					headers: bt_tracker_headers)
	{
	if ( c$id in bt_tracker_conns )
		{
		local id = bt_tracker_conns[c$id];
		print bt_tracker_log,
			fmt("%s [status:%d]",
				bt_log_tag(c$id, id, "response", F), status);
		}
	}

event bt_tracker_weird(c: connection, is_orig: bool, msg: string)
	{
	local id = (c$id in bt_tracker_conns) ? bt_tracker_conns[c$id] : 0;
	print bt_tracker_log,
		fmt("%s [%s]", bt_log_tag(c$id, id, "<weird>", is_orig), msg);

	event conn_weird(msg, c);
	}

event connection_state_remove(c: connection)
	{
	if ( c$id !in bt_tracker_conns )
		return;

	local id = bt_tracker_conns[c$id];
	delete bt_tracker_conns[c$id];

	print bt_tracker_log,
		fmt("%s [duration:%.06f total:%d]",
			# Ideally the direction here wouldn't be T or F
			# but both, displayed as "<>".
			bt_log_tag(c$id, id, "<closed>", T), c$duration,
			c$orig$size + c$resp$size);
	}
