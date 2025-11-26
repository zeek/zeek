global num_connections: count = 0;

event new_connection(c: connection)
	{
	num_connections += 1;
	}

event zeek_done()
	{
	print fmt("Found %d connections", num_connections);
	}
