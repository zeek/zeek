# @TEST-PORT: BROKER_PORT
# @TEST-REQUIRES: zeek --help 2>&1 | grep -q mem-leaks
# @TEST-GROUP: leaks

# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run clone "zeek -m -b ../clone.zeek >clone.out"
# @TEST-EXEC: btest-bg-run master "zeek -b ../master.zeek >master.out"

# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff clone/clone.out

@TEST-START-FILE master.zeek

redef exit_only_after_terminate = T;
global query_timeout = 1sec;

global ready: event();

global h: opaque of Broker::Store;

function print_index(k: any)
        {
        when ( local r = Broker::get(h, k) )
                {
                print "master", k, r$status, r$result;
                }
        timeout query_timeout
                {
                print "master", fmt("clone <timeout for %s>", k);
                }
        }

event done()
	{
	terminate();
	}

event inserted()
	{
	Broker::erase(h, "four");
	
	print("----");
	print_index("one");
	print_index("two");
	print_index(vector(1,2));
	print_index("three");
	print_index("four");
	print_index("five");
	print_index("six");
        schedule 2secs { done() };
	}

event zeek_init()
	{
	Broker::auto_publish("bro/events", done);
	Broker::subscribe("bro/");

	h = Broker::create_master("test");
	Broker::put(h, "one", "110");
	Broker::put(h, "two", 223);
	Broker::put(h, vector(1,2), 1947/tcp);
	
	Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event insert_more()
	{
	Broker::put(h, "three", 3.14);
	Broker::put(h, "four", 1.2.3.4);
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
        schedule 4secs { insert_more() };
	}

@TEST-END-FILE


@TEST-START-FILE clone.zeek

redef exit_only_after_terminate = T;

global query_timeout = 1sec;

global h: opaque of Broker::Store;


global inserted: event();

function print_index(k: any)
        {
        when ( local r = Broker::get(h, k) )
                {
                print "clone", k, r$status, r$result;
                }
        timeout query_timeout
                {
                print "clone", fmt("clone <timeout for %s>", k);
                }
        }

event lookup(stage: count)
	{
	print("----");
	print_index("one");
	print_index("two");
	print_index(vector(1,2));
	print_index("three");
	print_index("four");
	print_index("five");
	print_index("six");
	
	if ( stage == 1 )
		schedule 4secs { lookup(2) };

	if ( stage == 2 )
		{
		Broker::put(h, "five", "555");
		Broker::put(h, "six", "666");
		event inserted();
		schedule 2secs { lookup(3) };
		}
	}

event done()
	{
	terminate();
	}

event zeek_init()
	{
	Broker::auto_publish("bro/events", inserted);
	Broker::subscribe("bro/");
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	h = Broker::create_clone("test");
	schedule 2secs { lookup(1) };
	}

@TEST-END-FILE

