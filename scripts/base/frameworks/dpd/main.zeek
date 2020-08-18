##! Activates port-independent protocol detection and selectively disables
##! analyzers if protocol violations occur.

module DPD;

export {
	## Add the DPD logging stream identifier.
	redef enum Log::ID += { LOG };

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
};

event zeek_init() &priority=5
	{
	Log::create_stream(DPD::LOG, [$columns=Info, $path="dpd"]);
	}

event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=10
	{
	local analyzer = Analyzer::name(atype);

	# This is okay even if the service isn't present.
	delete c$service[fmt("-%s", analyzer)];

	add c$service[analyzer];
	}

event protocol_violation(c: connection, atype: Analyzer::Tag, aid: count,
                         reason: string) &priority=10
	{
	local analyzer = Analyzer::name(atype);
	# If the service hasn't been confirmed yet, don't generate a log message
	# for the protocol violation.
	if ( analyzer !in c$service )
		return;

	delete c$service[analyzer];
	add c$service[fmt("-%s", analyzer)];

	local info: Info;
	info$ts=network_time();
	info$uid=c$uid;
	info$id=c$id;
	info$proto=get_conn_transport_proto(c$id);
	info$analyzer=analyzer;
	info$failure_reason=reason;
	c$dpd = info;
	}

event protocol_violation(c: connection, atype: Analyzer::Tag, aid: count, reason: string) &priority=5
	{
	if ( atype in ignore_violations )
		return;

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

event protocol_violation(c: connection, atype: Analyzer::Tag, aid: count,
				reason: string) &priority=-5
	{
	if ( c?$dpd )
		{
		Log::write(DPD::LOG, c$dpd);
		delete c$dpd;
		}
	}
