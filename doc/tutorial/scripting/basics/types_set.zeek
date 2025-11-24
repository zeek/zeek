event zeek_init()
	{
	# Create a set of ports, order does NOT matter. The set(...) syntax
	# is used to create a new set.
	local safe_ports: set[port] = set(80/tcp, 443/tcp, 53/udp);

	# Check membership with 'in', or negate it with '!in'
	if ( 22/tcp !in safe_ports )
		print "SSH traffic is not on a safe port!";

	# Add elements with 'add'
	add safe_ports[22/tcp];

	# Notice the '!in' changed to just 'in'
	if ( 22/tcp in safe_ports )
		print "Now that port is safe!";

	# Remove elements with 'delete'
	delete safe_ports[22/tcp];

	# Back to '!in'
	if ( 22/tcp !in safe_ports )
		print "Oh, it's not safe... again";

	# Loop through all elements with a simple 'for' loop. This makes a variable
	# 'safe_port' available within the body of the loop for each iteration.
	# Since this is an unordered set, the order the ports get printed may not
	# be consistent.
	for ( safe_port in safe_ports )
		{
		print fmt("%s is a safe port", safe_port);
		}
	}
