##! Creates the now deprecated dpd.logfile.
# Remove in v8.1

module DPD;

export {
	## Add the DPD logging stream identifier.
	redef enum Log::ID += { LOG };

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## The record type defining the columns to log in the DPD logging stream.
	type Info: record {
		## Timestamp for when protocol analysis failed.
		ts:             time            &log;
		## Connection unique ID.
		uid:            string          &log;
		## Connection ID containing the 4-tuple which identifies endpoints.
		id:             conn_id         &log;
		## Transport protocol for the violation.
		proto:          transport_proto &log;
		## The analyzer that generated the violation.
		analyzer:       string          &log;
		## The textual reason for the analysis failure.
		failure_reason: string          &log;
	};
}

redef record connection += {
	dpd: Info &optional;
	## The set of services (analyzers) for which Zeek has observed a
	## violation after the same service had previously been confirmed.
	service_violation: set[string] &default=set() &ordered &deprecated="Remove in v8.1. Consider using failed_analyzers instead";

};

event zeek_init() &priority=5
	{
	Log::create_stream(DPD::LOG, Log::Stream($columns=Info, $path="dpd", $policy=log_policy));
	}

# before the same event in dpd.zeek
event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo) &priority=15
	{
	if ( ! is_protocol_analyzer(atype) && ! is_packet_analyzer(atype) )
		return;

	if ( ! info?$c )
		return;

	local c = info$c;
	local analyzer = Analyzer::name(atype);
	# If the service hasn't been confirmed yet, or already failed,
	# don't generate a log message for the protocol violation.
	if ( analyzer !in c$service || analyzer in c$service_violation )
		return;

	add c$service_violation[analyzer];

	local dpd: Info;
	dpd$ts = network_time();
	dpd$uid = c$uid;
	dpd$id = c$id;
	dpd$proto = get_port_transport_proto(c$id$orig_p);
	dpd$analyzer = analyzer;

	# Encode data into the reason if there's any as done for the old
	# analyzer_violation event, previously.
	local reason = info$reason;
	if ( info?$data )
		{
		local ellipsis = |info$data| > 40 ? "..." : "";
		local data = info$data[0:40];
		reason = fmt("%s [%s%s]", reason, data, ellipsis);
		}

	dpd$failure_reason = reason;
	c$dpd = dpd;
	}

event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo ) &priority=-5
	{
	if ( ! is_protocol_analyzer(atype) && ! is_packet_analyzer(atype) )
		return;

	if ( ! info?$c )
		return;

	if ( info$c?$dpd )
		{
		Log::write(DPD::LOG, info$c$dpd);
		delete info$c$dpd;
		}
	}

