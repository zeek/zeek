##! Logging analyzer  violations into analyzer.log

@load base/frameworks/logging
@load ./main

module Analyzer::Logging;

export {
	## Add the analyzer logging stream identifier.
	redef enum Log::ID += { LOG };

	## The record type defining the columns to log in the analyzer logging stream.
	type Info: record {
		## Timestamp of the violation.
		ts:             time              &log;
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
		failure_reason: string            &log;
		## Data causing failure or violation if available. Truncated
		## to :zeek:see:`Analyzer::Logging::failure_data_max_size`.
		failure_data:   string            &log &optional;
	};

	## If a violation contains information about the data causing it,
	## include at most this many bytes of it in the log.
	option failure_data_max_size = 40;

	## An event that can be handled to access the :zeek:type:`Analyzer::Logging::Info`
	## record as it is sent on to the logging framework.
	global log_analyzer: event(rec: Info);

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;
}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $path="analyzer", $ev=log_analyzer, $policy=log_policy]);
	}

function log_analyzer_failure(ts: time, atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	local rec = Info(
		$ts=ts,
		$analyzer_kind=Analyzer::kind(atype),
		$analyzer_name=Analyzer::name(atype),
		$failure_reason=info$reason
	);

	if ( info?$c )
		{
		rec$id = info$c$id;
		rec$uid = info$c$uid;
		}

	if ( info?$f )
		{
		rec$fuid = info$f$id;
		# If the confirmation didn't have a connection, but the
		# fa_file object has exactly one, use it.
		if ( ! rec?$uid && info$f?$conns && |info$f$conns| == 1 )
			{
			for ( _, c in info$f$conns )
				{
				rec$id = c$id;
				rec$uid = c$uid;
				}
			}
		}

	if ( info?$data )
		{
		if ( failure_data_max_size > 0 )
			rec$failure_data = info$data[0:failure_data_max_size];
		else
			rec$failure_data = info$data;
		}

	Log::write(LOG, rec);
	}

# event currently is only raised for protocol analyzers; we do not fail packet and file analyzers
event analyzer_failed(ts: time, atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	if ( ! is_protocol_analyzer(atype) )
		return;

	if ( ! info?$c )
		return;

	# log only for previously confirmed service that did not already log violation
	# note that analyzers can fail repeatedly in some circumstances - e.g. when they
	# are re-attached by the dynamic protocol detection due to later data.
	local analyzer_name = Analyzer::name(atype);
	if ( analyzer_name !in info$c$service || analyzer_name in info$c$failed_analyzers )
		return;

	log_analyzer_failure(ts, atype, info);
	}

# log packet and file analyzers here separately
event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo )
	{
	if ( is_protocol_analyzer(atype) )
		return;

	log_analyzer_failure(network_time(), atype, info);
	}

