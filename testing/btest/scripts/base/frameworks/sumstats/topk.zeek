# @TEST-EXEC: zeek %INPUT
# @TEST-EXEC: btest-diff .stdout

event zeek_init() &priority=5
	{
	local r1: SumStats::Reducer = [$stream="test.metric", 
	                               $apply=set(SumStats::TOPK)];
	# Merge two empty sets
	local topk1: opaque of topk = topk_init(4);
	local topk2: opaque of topk = topk_init(4);
	topk_merge(topk1, topk2);

	SumStats::create([$name="topk-test",
	                  $epoch=3secs,
	                  $reducers=set(r1),
	                  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["test.metric"];
	                  	local s: vector of SumStats::Observation;
	                  	s = topk_get_top(r$topk, 5);
	                  	
	                  	print fmt("Top entries for key %s", key$str);
	                  	for ( element in s ) 
	                  		{
	                  		print fmt("Num: %d, count: %d, epsilon: %d", s[element]$num, topk_count(r$topk, s[element]), topk_epsilon(r$topk, s[element]));
	                  		}
	                  	}]);


	const loop_v: vector of count = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100};

	local a: count;
	a = 0;

	for ( i in loop_v ) 
		{
		a = a + 1;
		for ( j in loop_v )
			{
			if ( i < j ) 
				SumStats::observe("test.metric", [$str="counter"], [$num=a]);
			}
		}
	

	SumStats::observe("test.metric", [$str="two"], [$num=1]);
	SumStats::observe("test.metric", [$str="two"], [$num=1]);
	}
