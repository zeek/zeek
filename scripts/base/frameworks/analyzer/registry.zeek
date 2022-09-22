##! Analyzer registry tracking the relationship between protocol analyzers
##! and logs or features they provide.


module Analyzer::Registry;

export {
	# Wrong/bad name?
	type AnalyzerClass: enum {
		PROTOCOL,
		FILE,
		PACKET,
	};

	type LogOptions: record {
		event_groups: set[string] &default=set();
	};

	type AnalyzerLogInfo: record {
		id: Log::ID;
		options: LogOptions;
	};

	## Information / Metadata attached to a given protocol or file analyzer.
	## Maybe: AnalyzerDescription ?
	type AnalyzerInfo: record {
		atype: AllAnalyzers::Tag;
		aclass: string &default="protocol";  # ? enum?
		logs: table[Log::ID] of AnalyzerLogInfo &default=table();

		# XXX: Only set on enumerate as not updated dynamically.
		#      Or hook into analyzer/main.zeek and update the registry.
		enabled: bool &optional;
	};

	# --- Registration functions used by analyzer scripts
	#
	## For the given analyzer, register a log with optional LogOptions
	global register_log: function(atype: AllAnalyzers::Tag, log_id: Log::ID,
	                              log_options: LogOptions &default=LogOptions());


	# --- User functions

	## Enumerate all available AnalyzerInfo records.
	global enumerate: function(): vector of AnalyzerInfo;


	## Disable all registered logs for the given analyzer.
	##
	## Optimized: Disable events related to this log stream if provided
	## Naive: Call Log::disable_stream(Log::ID)
	## TBD: Or do both, actually.
	global disable_logs: function(atype: AllAnalyzers::Tag);

	## Disable just one specific log of the given analyzer.
	##
	## Optimized: Disable events related to this log stream if provided
	## Naive: Call Log::disable_stream(Log::ID)
	## TBD: Or do both, actually.
	global disable_log: function(atype: AllAnalyzers::Tag, id: Log::ID);
}



global analyzer_infos: table[AllAnalyzers::Tag] of AnalyzerInfo;

function register_log(atype: AllAnalyzers::Tag, id: Log::ID, options: LogOptions)
	{
	if ( atype !in analyzer_infos )
		analyzer_infos[atype] = AnalyzerInfo($atype=atype);

	analyzer_infos[atype]$logs[id] = AnalyzerLogInfo($id=id, $options=options);
	}


function enumerate(): vector of AnalyzerInfo
	{
	local values: vector of AnalyzerInfo;
	for ( _, ai in analyzer_infos )
		{
		local aic = copy(ai);
		aic$enabled = T;  # TODO, need a is_analyzer_enabled() ?
		values += aic;
		}

	return values;
	}


# Minimal example showing how analyzers would register information about
# themselves.

module Examples;

@load base/protocols/dns
@load base/protocols/http
@load base/protocols/syslog


# Script of analyzers would add information about themselves to the registry.
event zeek_init()
	{
	Analyzer::Registry::register_log(Analyzer::ANALYZER_HTTP, HTTP::LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_SYSLOG, Syslog::LOG);

	Analyzer::Registry::register_log(Analyzer::ANALYZER_DNS, DNS::LOG,
	                                 [$event_groups=set("dns-logging")]);
	}

event zeek_done()
	{
	for ( _, ai in Analyzer::Registry::enumerate() )
		{
		print to_json(ai);
		}
	}
