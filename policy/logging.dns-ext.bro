@load global-ext
@load dns-ext

module DNS;

export {
	# Which DNS queries to record.
	# Choices are: Inbound, Outbound, Enabled, Disabled
	const query_logging = Enabled &redef;

	# If set to T, this will split inbound and outbound requests
	# into separate files.  F merges everything into a single file.
	const split_log_file = F &redef;
	
	# Make this value true to reduce the logs to only what's being 
	# queried for
	const minimal_logging = F &redef;
}

event bro_init()
	{
	LOG::create_logs("dns-ext", query_logging, split_log_file, T);
	
	if ( minimal_logging )
		LOG::define_header("dns-ext", cat_sep("\t", "\\N",
		                                      "ts", "orig_h", 
		                                      "query_type", "query"));
	else
		LOG::define_header("dns-ext", cat_sep("\t", "", 
		                                      "ts",
		                                      "orig_h", "orig_p",
		                                      "resp_h", "resp_p",
		                                      "proto", "query_type", "query_class",
		                                      "query", "transaction_id",
		                                      "ttl", "flags", "error", "replies"));
	
	}

event dns_ext(id: conn_id, di: dns_ext_session_info) &priority=-10
	{
	local log = LOG::get_file_by_id("dns-ext", id, F);
	
	if ( minimal_logging )
		{
		print log, cat_sep("\t", "\\N",
		                   di$ts,
		                   id$orig_h,
		                   query_types[di$qtype],
		                   di$query);
		}
	else
		{
		local flags: set[string];
		if ( di$RD )
			add flags["RD"];
		if ( di$RA )
			add flags["RA"];
		if ( di$TC )
			add flags["TC"];
		if ( di$QR )
			add flags["QR"];
		if ( di$Z )
			add flags["Z"];
		if ( di$AA )
			add flags["AA"];

		print log, cat_sep("\t", "\\N",
		                   di$ts,
		                   id$orig_h, port_to_count(id$orig_p),
		                   id$resp_h, port_to_count(id$resp_p),
		                   get_port_transport_proto(id$resp_p),
		                   query_types[di$qtype],
		                   dns_class[di$qclass],
		                   di$query, 
		                   fmt("%04x", di$trans_id),
		                   fmt("%.0f", interval_to_double(di$TTL)),
		                   fmt_str_set(flags, /!!!!/),
		                   base_error[di$rcode],
		                   fmt_str_set(di$replies, /!!!!/)
		                   );
		}
	}