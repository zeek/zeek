# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

# This used to lead to an assertion failure in the ZAM compiler due to
# a bug in how it computed the lifetime of loops nested via inlining.

function is_local(host: addr): bool
	{
	for ( local_net in set(10.0.0.0/8) )
		if ( host in local_net )
			return T;
	return F;
	}

event zeek_init()
	{
        for ( host_addr in set(127.0.0.1) )
                {
                if ( is_local(host_addr) )
                        next;
                }

	print "I compiled and ran!";
	}
