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

		## Disabled analyzer IDs.  This is only for internal tracking
		## so as to not attempt to disable analyzers multiple times.
		disabled_aids:  set[count];
	};

	## Ignore violations which go this many bytes into the connection.
	## Set to 0 to never ignore protocol violations.
	const ignore_violations_after = 10 * 1024 &redef;
}

redef record connection += {
	dpd: Info &optional;
};

event bro_init() &priority=5
	{
	Log::create_stream(DPD::LOG, [$columns=Info]);
	}

event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=10
	{
	local analyzer = Analyzer::name(atype);

	if ( fmt("-%s",analyzer) in c$service )
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
	if ( !c?$dpd || aid in c$dpd$disabled_aids )
		return;

	local size = c$orig$size + c$resp$size;
	if ( ignore_violations_after > 0 && size > ignore_violations_after )
		return;

	# Disable the analyzer that raised the last core-generated event.
	disable_analyzer(c$id, aid);
	add c$dpd$disabled_aids[aid];
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
