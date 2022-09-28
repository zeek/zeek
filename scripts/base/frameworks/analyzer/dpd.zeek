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

	## Ongoing DPD state tracking information.
	type State: record {
		## Current number of protocol violations seen per analyzer instance.
		violations: table[count] of count;
	};

	## Number of protocol violations to tolerate before disabling an analyzer.
	option max_violations: table[Analyzer::Tag] of count = table() &default = 5;

	## Analyzers which you don't want to throw
	option ignore_violations: set[Analyzer::Tag] = set();

	## Ignore violations which go this many bytes into the connection.
	## Set to 0 to never ignore protocol violations.
	option ignore_violations_after = 10 * 1024;
}

redef record connection += {
	dpd: Info &optional;
	dpd_state: State &optional;
	## The set of services (analyzers) for which Zeek has observed a
	## violation after the same service had previously been confirmed.
	service_violation: set[string] &default=set();
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
	# If the service hasn't been confirmed yet, don't generate a log message
	# for the protocol violation.
	if ( analyzer !in c$service )
		return;

	delete c$service[analyzer];
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

	if ( ! c?$dpd_state )
		{
		local s: State;
		c$dpd_state = s;
		}

	if ( aid in c$dpd_state$violations )
		++c$dpd_state$violations[aid];
	else
		c$dpd_state$violations[aid] = 1;

	if ( c?$dpd || c$dpd_state$violations[aid] > max_violations[atype] )
		{
		# Disable an analyzer we've previously confirmed, but is now in
		# violation, or else any analyzer in excess of the max allowed
		# violations, regardless of whether it was previously confirmed.
		disable_analyzer(c$id, aid, F);
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
