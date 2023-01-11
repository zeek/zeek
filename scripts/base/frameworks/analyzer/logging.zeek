##! Logging analyzer confirmations and violations into analyzer.log

@load base/frameworks/config
@load base/frameworks/logging

@load ./main

module Analyzer::Logging;

export {
	## Add the analyzer logging stream identifier.
	redef enum Log::ID += { LOG };

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## The record type defining the columns to log in the analyzer logging stream.
	type Info: record {
		## Timestamp of confirmation or violation.
		ts:             time              &log;
		## What caused this log entry to be produced. This can
		## currently be "violation" or "confirmation".
		cause:          string            &log;
		## The kind of analyzer involved. Currently "packet", "file"
		## or "protocol".
		analyzer_kind:  string            &log;
		## The name of the analyzer as produced by :zeek:see:`Analyzer::name`
		## for the analyzer's tag.
		analyzer_name:  string            &log;
		## Connection UID if available.
		uid:            string            &log &optional;
		## File UID if available.
		fuid:           string            &log &optional;
		## Connection identifier if available
		id:             conn_id           &log &optional;

		## Failure or violation reason, if available.
		failure_reason: string            &log &optional;

		## Data causing failure or violation if available. Truncated
		## to :zeek:see:`Analyzer::Logging::failure_data_max_size`.
		failure_data:   string            &log &optional;
	};

	## Enable logging of analyzer violations and optionally confirmations
	## when :zeek:see:`Analyzer::Logging::include_confirmations` is set.
	option enable = T;

	## Enable analyzer_confirmation. They are usually less interesting
	## outside of development of analyzers or troubleshooting scenarios.
	## Setting this option may also generated multiple log entries per
	## connection, minimally one for each conn.log entry with a populated
	## service field.
	option include_confirmations = F;

	## If a violation contains information about the data causing it,
	## include at most this many bytes of it in the log.
	option failure_data_max_size = 40;

	## Set of analyzers for which to not log confirmations or violations.
	option ignore_analyzers: set[AllAnalyzers::Tag] = set();
}


event zeek_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $path="analyzer", $policy=log_policy,
	                         $event_groups=set("Analyzer::Logging")]);

	local enable_handler = function(id: string, new_value: bool): bool {
		if ( new_value )
		    Log::enable_stream(LOG);
		else
		    Log::disable_stream(LOG);

		return new_value;
	};
	Option::set_change_handler("Analyzer::Logging::enable", enable_handler);

	local include_confirmations_handler = function(id: string, new_value: bool): bool {
		if ( new_value )
		    enable_event_group("Analyzer::Logging::include_confirmations");
		else
		    disable_event_group("Analyzer::Logging::include_confirmations");

		return new_value;
	};
	Option::set_change_handler("Analyzer::Logging::include_confirmations",
	                           include_confirmations_handler);

	# Call the handlers directly with the current values to avoid config
	# framework interactions like creating entries in config.log.
	enable_handler("Analyzer::Logging::enable", Analyzer::Logging::enable);
	include_confirmations_handler("Analyzer::Logging::include_confirmations",
	                              Analyzer::Logging::include_confirmations);

	}

function analyzer_kind(atype: AllAnalyzers::Tag): string
	{
	if ( is_protocol_analyzer(atype) )
		return "protocol";
	else if ( is_packet_analyzer(atype) )
		return "packet";
	else if ( is_file_analyzer(atype) )
		return "file";

	Reporter::warning(fmt("Unknown kind of analyzer %s", atype));
	return "unknown";
	}

function populate_from_conn(rec: Info, c: connection)
	{
	rec$id = c$id;
	rec$uid = c$uid;
	}

function populate_from_file(rec: Info, f: fa_file)
	{
	rec$fuid = f$id;
	# If the confirmation didn't have a connection, but the
	# fa_file object has has exactly one, use it.
	if ( ! rec?$uid && f?$conns && |f$conns| == 1 )
		{
		for ( _, c in f$conns )
			{
			rec$id = c$id;
			rec$uid = c$uid;
			}
		}
	}

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo) &group="Analyzer::Logging::include_confirmations"
	{
	if ( atype in ignore_analyzers )
		return;

	local rec = Info(
		$ts=network_time(),
		$cause="confirmation",
		$analyzer_kind=analyzer_kind(atype),
		$analyzer_name=Analyzer::name(atype),
	);

	if ( info?$c )
		populate_from_conn(rec, info$c);

	if ( info?$f )
		populate_from_file(rec, info$f);

	Log::write(LOG, rec);
	}

event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	if ( atype in ignore_analyzers )
		return;

	local rec = Info(
		$ts=network_time(),
		$cause="violation",
		$analyzer_kind=analyzer_kind(atype),
		$analyzer_name=Analyzer::name(atype),
		$failure_reason=info$reason,
	);

	if ( info?$c )
		populate_from_conn(rec, info$c);

	if ( info?$f )
		populate_from_file(rec, info$f);

	if ( info?$data )
		{
		if ( failure_data_max_size > 0 )
			rec$failure_data = info$data[0:failure_data_max_size];
		else
			rec$failure_data = info$data;
		}

	Log::write(LOG, rec);
	}
