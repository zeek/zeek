# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: grep "error" output >output2
# @TEST-EXEC: for i in 1 2 3 4 5; do cat output2 | cut -d'|' -f$i >>out; done
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

@load base/utils/queue

global q: Queue::Queue = Queue::init();

type myrec: record {
	a: bool &default=T;
	b: string &default="hi";
	c: string &optional;
};

function bar(c: count)
	{
	local rval: vector of string = vector();
	Queue::get_vector(q, rval);
	print rval;
	Queue::get_vector(q, rval);
	print rval;
	}

function foo(s: string, c: count)
	{
	bar(c + 42);
	}

event zeek_init()
	{
	Queue::put(q, "hello");
	Queue::put(q, "goodbye");
	Queue::put(q, "test");
	Queue::put(q, myrec());
	Queue::put(q, "asdf");
	Queue::put(q, 3);
	Queue::put(q, "jkl;");
	foo("hi", 13);
	}
