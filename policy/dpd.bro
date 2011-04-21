##! Activates port-independent protocol detection.

@load functions
@load signatures

module DPD;

# Add the DPD signatures.
redef signature_files += "dpd.sig";
redef enum Log::ID += { DPD };

export {
	type Info: record {
		ts:             time            &log;
		id:             conn_id         &log;
		proto:          transport_proto &log;
		analyzer:       string          &log;
		failure_reason: string          &log;
		packet_segment: string          &log;
	};
	
	## Size of the packet segment to display in the DPD log.
	const packet_segment_size: int = 255 &redef;
}

redef record connection += {
	dpd: Info &optional;
};

event bro_init()
	{
	Log::create_stream(DPD, [$columns=Info]);
	
	for ( a in dpd_config )
		{
		for ( p in dpd_config[a]$ports )
			{
			if ( p !in dpd_analyzer_ports )
				dpd_analyzer_ports[p] = set();
			add dpd_analyzer_ports[p][a];
			}
		}
	}

event protocol_confirmation(c: connection, atype: count, aid: count) &priority=10
	{
	if ( fmt("-%s",analyzer_name(atype)) in c$service )
		delete c$service[fmt("-%s", analyzer_name(atype))];

	add c$service[analyzer_name(atype)];
	}

event protocol_violation(c: connection, atype: count, aid: count,
				reason: string) &priority=10
	{
	if ( analyzer_name(atype) in c$service )
		delete c$service[analyzer_name(atype)];
	add c$service[fmt("-%s", analyzer_name(atype))];
	
	# Get the content of the currently analyzed packet and trim it down to a shorter size
	local packet_segment = sub_bytes(get_current_packet()$data, 0, packet_segment_size);
	
	Log::write(DPD, [$ts=network_time(),
	                 $id=c$id,
	                 $proto=get_conn_transport_proto(c$id),
	                 $analyzer=analyzer_name(atype),
	                 $failure_reason=reason,
	                 $packet_segment=fmt("%s", packet_segment)]);
	}

