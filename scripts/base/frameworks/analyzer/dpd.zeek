##! Disables analyzers if protocol violations occur, and add service information
##! to connection log.

@load ./main

module DPD;

export {
	## Deprecated, please see https://github.com/zeek/zeek/pull/4200 for details
	option max_violations: table[Analyzer::Tag] of count = table() &deprecated="Remove in v8.1: This has become non-functional in Zeek 7.2, see PR #4200" &default = 5;

	## Analyzers which you don't want to remove on violations.
	option ignore_violations: set[Analyzer::Tag] = set();

	## Ignore violations which go this many bytes into the connection.
	## Set to 0 to never ignore protocol violations.
	option ignore_violations_after = 10 * 1024;

	## Change behavior of service field in conn.log:
	## Failed services are no longer removed. Instead, for a failed
	## service, a second entry with a "-" in front of it is added.
	## E.g. a http connection with a violation would be logged as
	## "http,-http".
	option track_removed_services_in_connection = F;
}

redef record connection += {
	## The set of services (analyzers) for which Zeek has observed a
	## violation after the same service had previously been confirmed.
	service_violation: set[string] &default=set() &ordered;
};

# Add confirmed protocol analyzers to conn.log service field
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

# Remove failed analyzers from service field and add them to c$service_violation
# Low priority to allow other handlers to check if the analyzer was confirmed
event analyzer_failed(ts: time, atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo) &priority=-5
	{
	if ( ! is_protocol_analyzer(atype) )
		return;

	if ( ! info?$c )
		return;

	local c = info$c;
	local analyzer = Analyzer::name(atype);
	# If the service hasn't been confirmed yet, or already failed,
	# don't generate a log message for the protocol violation.
	if ( analyzer !in c$service )
		return;

	# If removed service tracking is active, don't delete the service here.
	if ( ! track_removed_services_in_connection )
		delete c$service[analyzer];

	# if statement is separate, to allow repeated removal of service, in case there are several
	# confirmation and violation events
	if ( analyzer !in c$service_violation )
		add c$service_violation[analyzer];

	# add "-service" to the list of services on removal due to violation, if analyzer was confirmed before
	if ( track_removed_services_in_connection && Analyzer::name(atype) in c$service )
		{
		local rname = cat("-", Analyzer::name(atype));
		if ( rname !in c$service )
			add c$service[rname];
		}
	}

event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo ) &priority=5
	{
	if ( ! is_protocol_analyzer(atype) )
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

	# analyzer already was removed or connection finished
	# let's still log this.
	if ( lookup_connection_analyzer_id(c$id, atype) == 0 )
		{
		event analyzer_failed(network_time(), atype, info);
		return;
		}

	local disabled = disable_analyzer(c$id, aid, F);

	# If analyzer was disabled, send failed event
	if ( disabled )
		event analyzer_failed(network_time(), atype, info);
	}

