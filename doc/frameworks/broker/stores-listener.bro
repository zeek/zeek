const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;

global h: opaque of Broker::Handle;
global expected_key_count = 4;
global key_count = 0;

function do_lookup(key: string)
	{
	when ( local res = Broker::lookup(h, Broker::data(key)) )
		{
		++key_count;
		print "lookup", key, res;

		if ( key_count == expected_key_count )
			terminate();
		}
	timeout 10sec
		{ print "timeout", key; }
	}

event ready()
	{
	h = Broker::create_clone("mystore");

	when ( local res = Broker::keys(h) )
		{
		print "clone keys", res;
		do_lookup(Broker::refine_to_string(Broker::vector_lookup(res$result, 0)));
		do_lookup(Broker::refine_to_string(Broker::vector_lookup(res$result, 1)));
		do_lookup(Broker::refine_to_string(Broker::vector_lookup(res$result, 2)));
		do_lookup(Broker::refine_to_string(Broker::vector_lookup(res$result, 3)));
		}
	timeout 10sec
		{ print "timeout"; }
	}

event bro_init()
	{
	Broker::enable();
	Broker::subscribe_to_events("bro/event/ready");
	Broker::listen(broker_port, "127.0.0.1");
	}
