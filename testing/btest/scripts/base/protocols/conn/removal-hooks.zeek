# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT >out
# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT test_unregister=T >>out
# @TEST-EXEC: btest-diff out

@load base/protocols/conn/removal-hooks

option test_unregister = F;

hook my_removal_hook(c: connection)
	{
	print "my_removal_hook", c$id;
	}

event new_connection(c: connection)
	{
	print "new_connection", c$id;
	print Conn::register_removal_hook(c, my_removal_hook);
	print Conn::register_removal_hook(c, my_removal_hook);
	print Conn::register_removal_hook(c, my_removal_hook);

	if ( test_unregister )
		{
		print Conn::unregister_removal_hook(c, my_removal_hook);
		print Conn::unregister_removal_hook(c, my_removal_hook);
		print Conn::unregister_removal_hook(c, my_removal_hook);
		}
	}
