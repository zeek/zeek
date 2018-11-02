# @TEST-EXEC-FAIL: bro -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

@load base/utils/queue

global q: Queue::Queue = Queue::init();

type myrec: record {
	a: bool &default=T;
	b: string &default="hi";
	c: string &optional;
};

function foo(mr: myrec)
	{
	print mr$a;
	print mr$c;
	print mr$b;
	}

event bro_init()
	{
	Queue::put(q, "hello");
	Queue::put(q, "goodbye");
	Queue::put(q, "test");
	Queue::put(q, myrec());

	local rval: vector of string = vector();
	Queue::get_vector(q, rval);
	print rval;
	}
