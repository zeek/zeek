# @TEST-EXEC: zeek %INPUT | sort >output
# @TEST-EXEC: btest-diff output

redef enum Notice::Type += {
	Test_Notice,
};

event zeek_init() &priority=5
	{
	local r1: SumStats::Reducer = [$stream="test.metric", $apply=set(SumStats::SUM)];
	SumStats::create([$name="test1",
	                  $epoch=3secs,
	                  $reducers=set(r1),
	                  #$threshold_val = SumStats::sum_threshold("test.metric"),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{ 
	                  	return result["test.metric"]$sum;
	                  	},
	                  $threshold=5.0,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = 
	                  	{
	                  	local r = result["test.metric"];
	                  	print fmt("THRESHOLD: hit a threshold value at %.0f for %s", r$sum, SumStats::key2str(key));
	                  	}
	                  ]);

	local r2: SumStats::Reducer = [$stream="test.metric", $apply=set(SumStats::SUM)];
	SumStats::create([$name="test2",
	                  $epoch=3secs,
	                  $reducers=set(r2),
	                  #$threshold_val = SumStats::sum_threshold("test.metric"),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{ 
	                  	return result["test.metric"]$sum;
	                  	},
	                  $threshold_series=vector(3.0,6.0,800.0),
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = 
	                  	{
	                  	local r = result["test.metric"];
	                  	print fmt("THRESHOLD_SERIES: hit a threshold series value at %.0f for %s", r$sum, SumStats::key2str(key));
	                  	}
	                  ]);

	local r3: SumStats::Reducer = [$stream="test.metric", $apply=set(SumStats::SUM)];
	local r4: SumStats::Reducer = [$stream="test.metric2", $apply=set(SumStats::SUM)];
	SumStats::create([$name="test3",
	                  $epoch=3secs,
	                  $reducers=set(r3, r4),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{ 
	                  	# Calculate a ratio between sums of two reducers.
	                  	if ( "test.metric2" in result && "test.metric" in result &&
	                  	     result["test.metric"]$sum > 0 )
	                  		return result["test.metric2"]$sum / result["test.metric"]$sum;
	                  	else
	                  		return 0.0;
	                  	},
	                  # Looking for metric2 sum to be 5 times the sum of metric
	                  $threshold=5.0, 
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local thold = result["test.metric2"]$sum / result["test.metric"]$sum;
	                  	print fmt("THRESHOLD WITH RATIO BETWEEN REDUCERS: hit a threshold value at %.0fx for %s", thold, SumStats::key2str(key));
	                  	}
	                  ]);

	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=3]);
	SumStats::observe("test.metric", [$host=6.5.4.3], [$num=2]);
	SumStats::observe("test.metric", [$host=7.2.1.5], [$num=1]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=3]);
	SumStats::observe("test.metric", [$host=7.2.1.5], [$num=1000]);
	SumStats::observe("test.metric2", [$host=7.2.1.5], [$num=10]);
	SumStats::observe("test.metric2", [$host=7.2.1.5], [$num=1000]);
	SumStats::observe("test.metric2", [$host=7.2.1.5], [$num=54321]);

	}
