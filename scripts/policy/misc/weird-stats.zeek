##! Log weird statistics.

@load base/frameworks/sumstats
@load base/frameworks/cluster

module WeirdStats;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	## How often stats are reported.
	const weird_stat_interval = 15min &redef;

	type Info: record {
		## Timestamp for the measurement.
		ts: time &log;
		## Name of the weird.
		name: string &log;
		## Number of times weird was seen since the last stats interval.
		num_seen: count &log;
	};

	global log_weird_stats: event(rec: Info);
}

global this_epoch_weirds: table[string] of double;
global last_epoch_weirds: table[string] of double;

function weird_epoch_results(ts: time, key: SumStats::Key, result: SumStats::Result)
	{
	this_epoch_weirds[key$str]=result["weirds.encountered"]$sum;
	}

function weird_epoch_finished(ts: time)
	{
	for ( n, v in this_epoch_weirds )
		{
		local last_count: double = 0.0;

		if ( n in last_epoch_weirds )
			last_count = last_epoch_weirds[n];

		local num_seen: double = v - last_count;

		if ( num_seen > 0.0 )
			Log::write(LOG, Info($ts = ts, $name = n,
			                     $num_seen = double_to_count(num_seen)));
		}

	last_epoch_weirds = this_epoch_weirds;
	this_epoch_weirds = table();
	}

event zeek_init() &priority=5
	{
	Log::create_stream(WeirdStats::LOG,
	                   [$columns = Info, $ev = log_weird_stats,
	                    $path="weird_stats", $policy=log_policy]);
	local r1 = SumStats::Reducer($stream = "weirds.encountered",
	                             $apply = set(SumStats::SUM));
	SumStats::create([$name = "weirds.statistics",
	                  $epoch = weird_stat_interval, $reducers = set(r1),
	                  $epoch_result = weird_epoch_results,
	                  $epoch_finished = weird_epoch_finished]);
	}

module SumStats;

function observe_weird_stats()
	{
	local rs = get_reporter_stats();

	for ( n, v in rs$weirds_by_type )
		SumStats::observe("weirds.encountered", SumStats::Key($str = n),
		                  SumStats::Observation($dbl=(v + 0.0)));
	}

@if ( Cluster::is_enabled() )

# I'm not sure if this is a hack or not: the manager will generate this
# event at the end of its epoch so workers can handle it just in time to
# generate the necessary stats.  Alternative may be workers generating the
# stats individually/proactively in their own finish_epoch, but that may be
# less synchronized?
event SumStats::cluster_ss_request(uid: string, ss_name: string, cleanup: bool) &priority=10
	{
	if ( ss_name != "weirds.statistics" )
		return;
	observe_weird_stats();
	}

@else

event SumStats::finish_epoch(ss: SumStat) &priority=10
	{
	if ( ss$name != "weirds.statistics" )
		return;

	observe_weird_stats();
	}

@endif
