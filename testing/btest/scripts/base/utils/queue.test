# @TEST-EXEC: zeek -b %INPUT > output
# @TEST-EXEC: btest-diff output

# This is loaded by default
@load base/utils/queue

event zeek_init()
	{
	local q = Queue::init([$max_len=2]);
	Queue::put(q, 1);
	Queue::put(q, 2);
	Queue::put(q, 3);
	Queue::put(q, 4);
	local test1: vector of count = vector();
	Queue::get_vector(q, test1);
	for ( i in test1 )
		print fmt("This is a get_vector test: %d", test1[i]);

	local test_val = Queue::get(q);
	print fmt("Testing get: %s", test_val);
	print fmt("Length after get: %d", Queue::len(q));

	local q2 = Queue::init([]);
	Queue::put(q2, "test 1");
	Queue::put(q2, "test 2");
	Queue::put(q2, "test 2");
	Queue::put(q2, "test 1");
	print fmt("Size of q2: %d", Queue::len(q2));
	local test3: vector of string = vector();
	Queue::get_vector(q2, test3);
	for ( i in test3 )
		print fmt("String queue value: %s", test3[i]);
	}
