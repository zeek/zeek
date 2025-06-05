##! Finds connections with protocols on non-standard ports with DPD.

@load base/frameworks/notice
@load base/utils/site
@load base/utils/conn-ids
@load base/protocols/conn/removal-hooks

module ProtocolDetector;

export {
	redef enum Notice::Type += {
		Protocol_Found,
		Server_Found,
	};

	# Table of (protocol, resp_h, resp_p) tuples known to be uninteresting
	# in the given direction.  For all other protocols detected on
	# non-standard ports, we raise a Protocol_Found notice.  (More specific
	# filtering can then be done via notice_filters.)
	#
	# Use 0.0.0.0 for to wildcard-match any resp_h.

	type dir: enum { NONE, INCOMING, OUTGOING, BOTH };

	option valids: table[AllAnalyzers::Tag, addr, port] of dir = {
		# A couple of ports commonly used for benign HTTP servers.

		# For now we want to see everything.

		# [Analyzer::ANALYZER_HTTP, 0.0.0.0, 81/tcp] = OUTGOING,
		# [Analyzer::ANALYZER_HTTP, 0.0.0.0, 82/tcp] = OUTGOING,
		# [Analyzer::ANALYZER_HTTP, 0.0.0.0, 83/tcp] = OUTGOING,
		# [Analyzer::ANALYZER_HTTP, 0.0.0.0, 88/tcp] = OUTGOING,
		# [Analyzer::ANALYZER_HTTP, 0.0.0.0, 8001/tcp] = OUTGOING,
		# [Analyzer::ANALYZER_HTTP, 0.0.0.0, 8090/tcp] = OUTGOING,
		# [Analyzer::ANALYZER_HTTP, 0.0.0.0, 8081/tcp] = OUTGOING,
		#
		# [Analyzer::ANALYZER_HTTP, 0.0.0.0, 6346/tcp] = BOTH, # Gnutella
		# [Analyzer::ANALYZER_HTTP, 0.0.0.0, 6347/tcp] = BOTH, # Gnutella
		# [Analyzer::ANALYZER_HTTP, 0.0.0.0, 6348/tcp] = BOTH, # Gnutella
	};

	# Set of analyzers for which we suppress Server_Found notices
	# (but not Protocol_Found).  Along with avoiding clutter in the
	# log files, this also saves memory because for these we don't
	# need to remember which servers we already have reported, which
	# for some can be a lot.
	option suppress_servers: set [AllAnalyzers::Tag] = {
		# Analyzer::ANALYZER_HTTP
	};

	# We consider a connection to use a protocol X if the analyzer for X
	# is still active (i) after an interval of minimum_duration, or (ii)
	# after a payload volume of minimum_volume, or (iii) at the end of the
	# connection.
	option minimum_duration = 30 secs;
	option minimum_volume = 4e3;	# bytes

	# How often to check the size of the connection.
	const check_interval = 5 secs;

	# Entry point for other analyzers to report that they recognized
	# a certain (sub-)protocol.
	global found_protocol: function(c: connection, analyzer: AllAnalyzers::Tag,
					protocol: string);

	# Table keeping reported (server, port, analyzer) tuples (and their
	# reported sub-protocols).
	global servers: table[addr, port, string] of set[string]
				&read_expire = 14 days;

	## Non-standard protocol port detection finalization hook.
	global finalize_protocol_detection: Conn::RemovalHook;
}

# Table that tracks currently active dynamic analyzers per connection.
global conns: table[conn_id] of set[AllAnalyzers::Tag];

# Table of reports by other analyzers about the protocol used in a connection.
global protocols: table[conn_id] of set[string];

type protocol : record {
	a: string;	# analyzer name
	sub: string;	# "sub-protocols" reported by other sources
};

function get_protocol(c: connection, a: AllAnalyzers::Tag) : protocol
	{
	local str = "";
	if ( c$id in protocols )
		{
		for ( p in protocols[c$id] )
			str = |str| > 0 ? fmt("%s/%s", str, p) : p;
		}

	return [$a=Analyzer::name(a), $sub=str];
	}

function fmt_protocol(p: protocol) : string
	{
	return p$sub != "" ? fmt("%s (via %s)", p$sub, p$a) : p$a;
	}

function do_notice(c: connection, a: AllAnalyzers::Tag, d: dir)
	{
	if ( d == BOTH )
		return;

	if ( d == INCOMING && Site::is_local_addr(c$id$resp_h) )
		return;

	if ( d == OUTGOING && ! Site::is_local_addr(c$id$resp_h) )
		return;

	local p = get_protocol(c, a);
	local s = fmt_protocol(p);

	NOTICE([$note=Protocol_Found,
		$msg=fmt("%s %s on port %s", id_string(c$id), s, c$id$resp_p),
		$sub=s, $conn=c]);

	# We report multiple Server_Found's per host if we find a new
	# sub-protocol.
	local known = [c$id$resp_h, c$id$resp_p, p$a] in servers;

	local newsub = F;
	if ( known )
		newsub = (p$sub != "" &&
			  p$sub !in servers[c$id$resp_h, c$id$resp_p, p$a]);

	if ( (! known || newsub) && a !in suppress_servers )
		{
		NOTICE([$note=Server_Found,
			$msg=fmt("%s: %s server on port %s%s", c$id$resp_h, s,
				c$id$resp_p, (known ? " (update)" : "")),
			$p=c$id$resp_p, $sub=s, $conn=c, $src=c$id$resp_h]);

		if ( ! known )
			servers[c$id$resp_h, c$id$resp_p, p$a] = set();

		add servers[c$id$resp_h, c$id$resp_p, p$a][p$sub];
		}
	}

function report_protocols(c: connection)
	{
	# We only report the connection if both sides have transferred data.
	if ( c$resp$size == 0 || c$orig$size == 0 )
		{
		delete conns[c$id];
		delete protocols[c$id];
		return;
		}

	local analyzers = conns[c$id];

	for ( a in analyzers )
		{
		if ( [a, c$id$resp_h, c$id$resp_p] in valids )
			do_notice(c, a, valids[a, c$id$resp_h, c$id$resp_p]);
		else if ( [a, 0.0.0.0, c$id$resp_p] in valids )
			do_notice(c, a, valids[a, 0.0.0.0, c$id$resp_p]);
		else
			do_notice(c, a, NONE);
		}

	delete conns[c$id];
	delete protocols[c$id];
	}

event ProtocolDetector::check_connection(c: connection)
	{
	if ( c$id !in conns )
		return;

	local duration = network_time() - c$start_time;
	local size = c$resp$size + c$orig$size;

	if ( duration >= minimum_duration || size >= minimum_volume )
		report_protocols(c);
	else
		{
		local delay = min_interval(minimum_duration - duration,
					   check_interval);
		schedule delay { ProtocolDetector::check_connection(c) };
		}
	}

hook finalize_protocol_detection(c: connection)
	{
	if ( c$id !in conns )
		{
		delete protocols[c$id];
		return;
		}

	# Reports all analyzers that have remained to the end.
	report_protocols(c);
	}

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo)
	{
	if ( ! is_protocol_analyzer(atype) )
		return;

	local c = info$c;

	# Don't report anything running on a well-known port.
	if ( c$id$resp_p in Analyzer::registered_ports(atype) )
		return;

	if ( c$id in conns )
		{
		local analyzers = conns[c$id];
		add analyzers[atype];
		}
	else
		{
		conns[c$id] = set(atype);
		Conn::register_removal_hook(c, finalize_protocol_detection);

		local delay = min_interval(minimum_duration, check_interval);
		schedule delay { ProtocolDetector::check_connection(c) };
		}
	}

function found_protocol(c: connection, atype: AllAnalyzers::Tag, protocol: string)
	{
	# Don't report anything running on a well-known port.
	if ( c$id$resp_p in Analyzer::registered_ports(atype) )
		return;

	if ( c$id !in protocols )
		protocols[c$id] = set();

	add protocols[c$id][protocol];
	Conn::register_removal_hook(c, finalize_protocol_detection);
	}
