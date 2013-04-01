# @TEST-EXEC: bro %INPUT
# @TEST-EXEC: btest-diff .stdout

event bro_init() &priority=5
	{
	local r1: Measurement::Reducer = [$stream="test.metric", 
	                                  $apply=set(Measurement::SUM, 
	                                             Measurement::VARIANCE, 
	                                             Measurement::AVERAGE, 
	                                             Measurement::MAX, 
	                                             Measurement::MIN, 
	                                             Measurement::STD_DEV,
	                                             Measurement::UNIQUE)];
	Measurement::create([$epoch=3secs,
	                     $reducers=set(r1),
	                     $epoch_finished(data: Measurement::ResultTable) = 
	                     	{
	                     	for ( key in data )
	                     		{
	                     		local r = data[key]["test.metric"];
	                     		print fmt("Host: %s - num:%d - sum:%.1f - var:%.1f - avg:%.1f - max:%.1f - min:%.1f - std_dev:%.1f - unique:%d", key$host, r$num, r$sum, r$variance, r$average, r$max, r$min, r$std_dev, r$unique);
	                     		}
	                     	}
		 ]);

	Measurement::add_data("test.metric", [$host=1.2.3.4], [$num=5]);
	Measurement::add_data("test.metric", [$host=1.2.3.4], [$num=22]);
	Measurement::add_data("test.metric", [$host=1.2.3.4], [$num=94]);
	Measurement::add_data("test.metric", [$host=1.2.3.4], [$num=50]);
	Measurement::add_data("test.metric", [$host=1.2.3.4], [$num=50]);

	Measurement::add_data("test.metric", [$host=6.5.4.3], [$num=2]);
	Measurement::add_data("test.metric", [$host=7.2.1.5], [$num=1]);
	}
