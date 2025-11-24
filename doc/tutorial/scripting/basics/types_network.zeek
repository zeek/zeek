event zeek_init()
	{
	# Setup some variables
	local dns_server: addr = 8.8.8.8;
	local internal_net: subnet = 10.0.0.0/8;
	local web_traffic: port = 80/tcp;

	# Check if dns_server is part of the internal subnet
	if ( dns_server in internal_net )
		print "DNS server is internal";
	else
		print "DNS server is external";

	# We can also natively check protocols based on the port if it's
	# a known port
	if ( web_traffic == 443/tcp )
		print "This is HTTPS";
	else
		print "This is another protocol";
	}
