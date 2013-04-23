# @TEST-EXEC: bro %INPUT
# @TEST-EXEC: btest-diff metrics.log

event bro_init() &priority=5
	{
	Metrics::add_filter("test.metric", 
		[$name="foo-bar",
		 $every=3secs,
		 $measure=set(Metrics::SUM, Metrics::VARIANCE, Metrics::AVG, Metrics::MAX, Metrics::MIN, Metrics::STD_DEV),
		 $period_finished=Metrics::write_log]);

	Metrics::add_data("test.metric", [$host=1.2.3.4], [$num=5]);
	Metrics::add_data("test.metric", [$host=1.2.3.4], [$num=22]);
	Metrics::add_data("test.metric", [$host=1.2.3.4], [$num=94]);
	Metrics::add_data("test.metric", [$host=1.2.3.4], [$num=50]);
	Metrics::add_data("test.metric", [$host=1.2.3.4], [$num=50]);

	Metrics::add_data("test.metric", [$host=6.5.4.3], [$num=2]);
	Metrics::add_data("test.metric", [$host=7.2.1.5], [$num=1]);
	}
