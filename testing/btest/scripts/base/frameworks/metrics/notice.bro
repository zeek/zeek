# @TEST-EXEC: bro %INPUT
# @TEST-EXEC: btest-diff notice.log


redef enum Notice::Type += {
	Test_Notice,
};

event bro_init() &priority=5
	{
	Metrics::add_filter("test.metric", 
		[$name="foo-bar",
		 $break_interval=3secs,
		 $note=Test_Notice,
		 $notice_threshold=2,
		 $log=F]);
	Metrics::add_data("test.metric", [$host=1.2.3.4], 3);
	Metrics::add_data("test.metric", [$host=6.5.4.3], 2);
	Metrics::add_data("test.metric", [$host=7.2.1.5], 1);
	}
