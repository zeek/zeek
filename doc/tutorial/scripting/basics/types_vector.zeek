event zeek_init()
	{
	# Create a vector of mail server addresses
	local mail_server_ips: vector of addr = vector(10.0.0.1, 10.0.0.2);

	# Access the first element (index starts at 0)
	print fmt("Primary mail server IP: %s", mail_server_ips[0]);

	# You can add another server to the end with +=
	mail_server_ips += 10.0.0.3;

	# Loop with a 'for' loop. Vectors provide both the index and the value.
	# We use the variable name '_' to indicate we don't care about the index.
	for ( _, server_ip in mail_server_ips )
		{
		print fmt("%s is a mail server IP", server_ip);
		}

	# You can also get the length of a vector, string, and more by surrounding
	# it with vertical bars (||)
	print fmt("There are %d IPs in the vector", |mail_server_ips|);
	}
