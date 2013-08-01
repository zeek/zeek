# @TEST-EXEC: bro -b %INPUT runnumber=1 >out
# @TEST-EXEC: bro -b %INPUT runnumber=2 >>out
# @TEST-EXEC: bro -b %INPUT runnumber=3 >>out
# @TEST-EXEC: btest-diff out

global runnumber: count &redef; # differentiate runs

global k1: opaque of topk &persistent;
global k2: opaque of topk &persistent;

event bro_init() 
	{

	k2 = topk_init(20);

	if ( runnumber == 1 )
		{
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
		}

	local s = topk_get_top(k1, 3);
	print topk_count(k1, "a");
	print topk_count(k1, "b");
	print topk_count(k1, "c");
	print topk_count(k1, "d");
	print topk_count(k1, "e");
	print topk_count(k1, "f");

	if ( runnumber == 2 ) 
		{
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
		}

	print s;

	}
