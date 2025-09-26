redef exit_only_after_terminate = T;

global h: opaque of Broker::Store;
global expected_key_count = 4;
global key_count = 0;

# Lookup a value in the store based on an arbitrary key string.
function do_lookup(key: string)
	{
	when ( local res = Broker::get(h, key) )
		{
		++key_count;
		print "lookup", key, res;

		# End after we iterated over looking up each key in the store twice.
		if ( key_count == expected_key_count * 2 )
			terminate();
		}
	# All data store queries must specify a timeout
	timeout 3sec
		{ print "timeout", key; }
	}

event check_keys()
	{
	# Here we just query for the list of keys in the store, and show how to
	# look up each one's value.
	when ( local res = Broker::keys(h) )
		{
		print "clone keys", res;

		if ( res?$result )
			{
			# Since we know that the keys we are storing are all strings,
			# we can conveniently cast the result of Broker::keys to
			# a native Bro type, namely 'set[string]'.
			for ( k in res$result as string_set )
				do_lookup(k);

			# Alternatively, we can use a generic iterator to iterate
			# over the results (which we know is of the 'set' type because
			# that's what Broker::keys() always returns).  If the keys
			# we stored were not all of the same type, then you would
			# likely want to use this method of inspecting the store's keys.
			local i = Broker::set_iterator(res$result);

			while ( ! Broker::set_iterator_last(i) )
				{
				do_lookup(Broker::set_iterator_value(i) as string);
				Broker::set_iterator_next(i);
				}
			}
		}
	# All data store queries must specify a timeout.
	# You also might see timeouts on connecting/initializing a clone since
	# it hasn't had time to get fully set up yet.
	timeout 1sec
		{
		print "timeout";
		schedule 1sec { check_keys() };
		}
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer added";
	# We could create a clone early, like in zeek_init and it will periodically
	# try to synchronize with its master once it connects, however, we just
	# create it now since we know the peer w/ the master store has just
	# connected.
	h = Broker::create_clone("mystore");

	event check_keys();
	}

event zeek_init()
	{
	Broker::listen("127.0.0.1");
	}
