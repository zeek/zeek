event zeek_init()
	{
	local subnets = vector(172.16.0.0/20, 172.16.16.0/20, 172.16.32.0/20, [2001:db8:b120::]/64);
	local addresses = vector(172.16.4.56, 172.16.47.254, 172.16.1.1, [2001:db8:b120::1]);

	for ( a in addresses )
		{
		for ( s in subnets )
			{
			if ( addresses[a] in subnets[s] )
				print fmt("%s belongs to subnet %s", addresses[a], subnets[s]);
			}
		}

	}
