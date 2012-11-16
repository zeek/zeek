# @TEST-EXEC: bro %INPUT
# @TEST-EXEC: btest-diff .stdout


redef enum Notice::Type += {
	Test_Notice,
};

event bro_init() &priority=5
	{
	Metrics::add_filter("test.metric", 
	                    [$name="foobar",
	                     $every=3secs,
	                     $measure=set(Metrics::SUM),
	                     $threshold=5,
	                     $threshold_crossed(index: Metrics::Index, val: Metrics::ResultVal) = {
	                     	print fmt("THRESHOLD: hit a threshold value at %.0f for %s", val$sum, Metrics::index2str(index));
	                     },
	                     $log=F]);

	Metrics::add_filter("test.metric", 
	                    [$name="foobar2",
	                     $every=3secs,
	                     $measure=set(Metrics::SUM),
	                     $threshold_series=vector(3,6,800),
	                     $threshold_crossed(index: Metrics::Index, val: Metrics::ResultVal) = {
	                     	print fmt("THRESHOLD_SERIES: hit a threshold series value at %.0f for %s", val$sum, Metrics::index2str(index));
		                 },
	                     $log=F]);
	Metrics::add_filter("test.metric", 
	                    [$every=3secs,
	                     $measure=set(Metrics::SUM),
	                     $threshold_func(index: Metrics::Index, val: Metrics::ResultVal) = {
	                     	# This causes any data added to be cross the threshold.
	                     	return T;
	                     },
	                     $threshold_crossed(index: Metrics::Index, val: Metrics::ResultVal) = {
	                     	print fmt("THRESHOLD_FUNC: hit a threshold function value at %.0f for %s", val$sum, Metrics::index2str(index));
	                     },
	                     $log=F]);

	Metrics::add_data("test.metric", [$host=1.2.3.4], [$num=3]);
	Metrics::add_data("test.metric", [$host=6.5.4.3], [$num=2]);
	Metrics::add_data("test.metric", [$host=7.2.1.5], [$num=1]);
	Metrics::add_data("test.metric", [$host=1.2.3.4], [$num=3]);
	Metrics::add_data("test.metric", [$host=7.2.1.5], [$num=1000]);
	}
