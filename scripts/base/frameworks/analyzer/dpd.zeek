##! Activates port-independent protocol detection and selectively disables
##! analyzers if protocol violations occur.

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

	## Deprecated, please see https://github.com/zeek/zeek/pull/4200 for details
	option max_violations: table[Analyzer::Tag] of count = table() &deprecated="Remove in v8.1: This has become non-functional in Zeek 7.2, see PR #4200" &default = 5;

	## Analyzers which you don't want to throw
	option ignore_violations: set[Analyzer::Tag] = set();

	## Ignore violations which go this many bytes into the connection.
	## Set to 0 to never ignore protocol violations.
	option ignore_violations_after = 10 * 1024;

	## Add removed services to conn.log, with a - in front of them.
	option track_removed_services_in_connection = F;
}

redef record connection += {
	dpd: Info &optional;
	## The set of services (analyzers) for which Zeek has observed a
	## violation after the same service had previously been confirmed.
	service_violation: set[string] &default=set() &ordered;
};

event zeek_init() &priority=5
	{
	Log::create_stream(DPD::LOG, [$columns=Info, $path="dpd", $policy=log_policy]);
	}

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo) &priority=10
	{
	if ( ! is_protocol_analyzer(atype) && ! is_packet_analyzer(atype) )
		return;

	if ( ! info?$c )
		return;

	local c = info$c;
	local analyzer = Analyzer::name(atype);
	add c$service[analyzer];
	}

event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo) &priority=10
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

event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo ) &priority=5
	{
	if ( ! is_protocol_analyzer(atype) && ! is_packet_analyzer(atype) )
		return;

	if ( ! info?$c || ! info?$aid )
		return;

	if ( atype in ignore_violations )
		return;

	local c = info$c;
	local aid = info$aid;
	local size = c$orig$size + c$resp$size;
	if ( ignore_violations_after > 0 && size > ignore_violations_after )
		return;

	local disabled = disable_analyzer(c$id, aid, F);

	# add "-service" to the list of services on removal due to violation, if analyzer was confirmed before
	if ( track_removed_services_in_connection && disabled && Analyzer::name(atype) in c$service )
		{
		local rname = cat("-", Analyzer::name(atype));
		if ( rname !in c$service )
			add c$service[rname];
		}

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
