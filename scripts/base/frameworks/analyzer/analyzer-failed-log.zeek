##! Logging analyzer  violations into analyzer-failed.log

@load base/frameworks/logging
@load ./main

module Analyzer::Logging;

export {
	## Add the analyzer logging stream identifier.
	redef enum Log::ID += { LOG };

	## The record type defining the columns to log in the analyzer-failed logging stream.
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
	global log_analyzer_failed: event(rec: Info);

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;
}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $path="analyzer-failed", $ev=log_analyzer_failed, $policy=log_policy]);
	}

event analyzer_failed(ts: time, atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
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
		rec$failure_data = info$data;

	Log::write(LOG, rec);
	}
