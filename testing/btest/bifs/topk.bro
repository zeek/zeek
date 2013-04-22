# @TEST-EXEC: bro -b %INPUT > out
# @TEST-EXEC: btest-diff out

event bro_init() 
	{
	local k1 = topk_init(2);
	
	# first - peculiarity check...
	topk_add(k1, "a");
	topk_add(k1, "b");
	topk_add(k1, "b");
	topk_add(k1, "c");

	local s = topk_get_top(k1, 5);
	print s;
 
	topk_add(k1, "d");
	s = topk_get_top(k1, 5);
	print s;
	
	topk_add(k1, "e");
	s = topk_get_top(k1, 5);
	print s;
	
	topk_add(k1, "f");
	s = topk_get_top(k1, 5);
	print s;
	
	topk_add(k1, "e");
	s = topk_get_top(k1, 5);
	print s;

	topk_add(k1, "g");
	s = topk_get_top(k1, 5);
	print s;

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
	

}
