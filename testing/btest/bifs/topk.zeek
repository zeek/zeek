# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

event zeek_init() 
	{
	local k1 = topk_init(2);
	
	# first - peculiarity check...
	topk_add(k1, "a");
	topk_add(k1, "b");
	topk_add(k1, "b");
	topk_add(k1, "c");

	local s = topk_get_top(k1, 5);
	print s;
	print topk_sum(k1);
	print topk_count(k1, "a");
	print topk_epsilon(k1, "a");
	print topk_count(k1, "b");
	print topk_epsilon(k1, "b");
	print topk_count(k1, "c");
	print topk_epsilon(k1, "c");
 
	topk_add(k1, "d");
	s = topk_get_top(k1, 5);
	print s;
	print topk_sum(k1);
	print topk_count(k1, "b");
	print topk_epsilon(k1, "b");
	print topk_count(k1, "c");
	print topk_epsilon(k1, "c");
	print topk_count(k1, "d");
	print topk_epsilon(k1, "d");
	
	topk_add(k1, "e");
	s = topk_get_top(k1, 5);
	print s;
	print topk_sum(k1);
	print topk_count(k1, "d");
	print topk_epsilon(k1, "d");
	print topk_count(k1, "e");
	print topk_epsilon(k1, "e");
	
	topk_add(k1, "f");
	s = topk_get_top(k1, 5);
	print s;
	print topk_sum(k1);
	print topk_count(k1, "f");
	print topk_epsilon(k1, "f");
	print topk_count(k1, "e");
	print topk_epsilon(k1, "e");
	
	topk_add(k1, "e");
	s = topk_get_top(k1, 5);
	print s;
	print topk_sum(k1);
	print topk_count(k1, "f");
	print topk_epsilon(k1, "f");
	print topk_count(k1, "e");
	print topk_epsilon(k1, "e");

	topk_add(k1, "g");
	s = topk_get_top(k1, 5);
	print s;
	print topk_sum(k1);
	print topk_count(k1, "f");
	print topk_epsilon(k1, "f");
	print topk_count(k1, "e");
	print topk_epsilon(k1, "e");
	print topk_count(k1, "g");
	print topk_epsilon(k1, "g");

	k1 = topk_init(100);
	topk_add(k1, "a");
	topk_add(k1, "b");
	topk_add(k1, "b");
	topk_add(k1, "c");
	topk_add(k1, "c");
	topk_add(k1, "c");
	topk_add(k1, "c");
	topk_add(k1, "c");
	topk_add(k1, "c");
	topk_add(k1, "d");
	topk_add(k1, "d");
	topk_add(k1, "d");
	topk_add(k1, "d");
	topk_add(k1, "e");
	topk_add(k1, "e");
	topk_add(k1, "e");
	topk_add(k1, "e");
	topk_add(k1, "e");
	topk_add(k1, "f");
	s = topk_get_top(k1, 3);
	print s;
	print topk_sum(k1);
	print topk_count(k1, "c");
	print topk_epsilon(k1, "c");
	print topk_count(k1, "e");
	print topk_epsilon(k1, "d");
	print topk_count(k1, "d");
	print topk_epsilon(k1, "d");
	
	local k3 = topk_init(2);
	topk_merge_prune(k3, k1);

	s = topk_get_top(k3, 3);
	print s;
	print topk_count(k3, "c");
	print topk_epsilon(k3, "c");
	print topk_count(k3, "e");
	print topk_epsilon(k3, "e");
	print topk_count(k3, "d");
	print topk_epsilon(k3, "d");
	
	topk_merge_prune(k3, k1);

	s = topk_get_top(k3, 3);
	print s;
	print topk_sum(k3); # this gives a warning and a wrong result.
	print topk_count(k3, "c");
	print topk_epsilon(k3, "c");
	print topk_count(k3, "e");
	print topk_epsilon(k3, "e");
	print topk_count(k3, "d");
	print topk_epsilon(k3, "d");

	k3 = topk_init(2);
	topk_merge(k3, k1);
	print s;
	print topk_sum(k3);
	print topk_count(k3, "c");
	print topk_epsilon(k3, "c");
	print topk_count(k3, "e");
	print topk_epsilon(k3, "e");
	print topk_count(k3, "d");
	print topk_epsilon(k3, "d");

	topk_merge(k3, k1);

	s = topk_get_top(k3, 3);
	print s;
	print topk_sum(k3);
	print topk_count(k3, "c");
	print topk_epsilon(k3, "c");
	print topk_count(k3, "e");
	print topk_epsilon(k3, "e");
	print topk_count(k3, "d");
	print topk_epsilon(k3, "d");

	local styped: vector of count;
	styped = topk_get_top(k3, 3);
	for ( i in styped )
	print i, styped[i];

	local anytyped: vector of any;
	anytyped = topk_get_top(k3, 3);
	for ( i in anytyped )
		print i, anytyped[i];

	local suntyped = topk_get_top(k3, 3);
	for ( i in suntyped )
		print i, suntyped[i];
}
