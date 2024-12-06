# @TEST-EXEC: zeek -b -C -r $TRACES/http/docker-http-upgrade.pcap %INPUT >out
# @TEST-EXEC: zeek-cut -m uid status_code method uri < http.log > http.log.cut
# @TEST-EXEC: btest-diff http.log.cut
# @TEST-EXEC: btest-diff out

@load base/protocols/http

# Forward "tcp" data as events via the stream event analyzer.
redef HTTP::upgrade_analyzers += {
	["tcp"] = Analyzer::ANALYZER_STREAM_EVENT,
};

event http_connection_upgrade(c: connection, protocol: string)
	{
	print c$uid, fmt("Connection upgraded to %s", protocol);
	}

redef record connection += {
	orig_data: string &default="";
	resp_data: string &default="";
};

function flush(c: connection)
	{
	# Don't copy this, it's not efficient.
	local orig_parts = split_string(c$orig_data, /[\r\n]+/);
	local resp_parts = split_string(c$resp_data, /[\r\n]+/);
	local i = 0;

	while ( i + 1 < |orig_parts| ) {
		print c$uid, "originator", orig_parts[i];
		++i;
	}
	c$orig_data = orig_parts[-1];

	i = 0;
	while ( i + 1 < |resp_parts| ) {
		print c$uid, "responder", resp_parts[i];
		++i;
	}
	c$resp_data = resp_parts[-1];
	}

event stream_deliver(c: connection, is_orig: bool, data: string)
	{
	if ( is_orig )
		c$orig_data += data;
	else
		c$resp_data += data;

	flush(c);
	}
