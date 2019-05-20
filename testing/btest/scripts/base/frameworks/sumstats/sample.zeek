# @TEST-EXEC: zeek %INPUT
# @TEST-EXEC: btest-diff .stdout

event zeek_init() &priority=5
	{
	local r1: SumStats::Reducer = [$stream="test.metric", 
	                               $apply=set(SumStats::SAMPLE), $num_samples=2];
	SumStats::create([$name="test",
	                  $epoch=3secs,
	                  $reducers=set(r1),
	                  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	print key$host;
	                  	local r = result["test.metric"];
	                  	print r$samples;
	                  	print r$sample_elements;
	                  	}]);

	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=5]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=22]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=94]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=50]);
	# I checked the random numbers. seems legit.
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=51]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=51]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=51]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=51]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=51]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=51]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=51]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=51]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=51]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=51]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=51]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=51]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=51]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=51]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=51]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=51]);

	SumStats::observe("test.metric", [$host=6.5.4.3], [$num=2]);
	SumStats::observe("test.metric", [$host=7.2.1.5], [$num=1]);
	}

