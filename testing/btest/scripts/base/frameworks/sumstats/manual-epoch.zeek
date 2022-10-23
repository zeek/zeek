# @TEST-EXEC: btest-bg-run standalone zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 15
# @TEST-EXEC: btest-diff standalone/.stdout

@load base/frameworks/sumstats

redef exit_only_after_terminate=T;

event second_test()
	{
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=5]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=22]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=94]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=50]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=50]);

	SumStats::observe("test.metric", [$host=6.5.4.3], [$num=2]);
	SumStats::observe("test.metric", [$host=7.2.1.5], [$num=1]);
	print "Performing second epoch with observations";
	local ret = SumStats::next_epoch("test");
	if ( ! ret )
		print "Return value false";
	}

event cont_test()
	{
	print "Performing first epoch, no observations";
	local ret = SumStats::next_epoch("test");
	if ( ! ret )
		print "Return value false";
	schedule 2secs { second_test() };
	}

event zeek_init() &priority=5
	{
	local r1: SumStats::Reducer = [$stream="test.metric",
	                               $apply=set(SumStats::SUM,
	                                          SumStats::VARIANCE,
	                                          SumStats::AVERAGE,
	                                          SumStats::MAX,
	                                          SumStats::MIN,
	                                          SumStats::STD_DEV,
	                                          SumStats::UNIQUE,
	                                          SumStats::HLL_UNIQUE)];
	SumStats::create([$name="test",
	                  $epoch=0secs,
	                  $reducers=set(r1),
	                  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["test.metric"];
	                  	print fmt("Host: %s - num:%d - sum:%.1f - var:%.1f - avg:%.1f - max:%.1f - min:%.1f - std_dev:%.1f - unique:%d - hllunique:%d", key$host, r$num, r$sum, r$variance, r$average, r$max, r$min, r$std_dev, r$unique, r$hll_unique);
	                  	terminate();
	                  	},
	                  $epoch_finished(ts: time) =
	                  	{
	                  	print "epoch_finished";
	                  	}]);

	schedule 1secs { cont_test() };
	}
