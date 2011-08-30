# @TEST-EXEC: bro %INPUT
# @TEST-EXEC: btest-diff notice.log


redef enum Notice::Type += {
	Test_Notice,
};

redef enum Metrics::ID += {
	TEST_METRIC,
};

event bro_init() &priority=5
	{
	Metrics::add_filter(TEST_METRIC, 
		[$name="foo-bar",
		 $break_interval=3secs,
		 $note=Test_Notice,
		 $notice_threshold=2,
		 $log=F]);
	Metrics::add_data(TEST_METRIC, [$host=1.2.3.4], 3);
	Metrics::add_data(TEST_METRIC, [$host=6.5.4.3], 2);
	Metrics::add_data(TEST_METRIC, [$host=7.2.1.5], 1);
	}
