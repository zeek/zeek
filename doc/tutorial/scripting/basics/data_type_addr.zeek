event zeek_init()
	{
	local ipv4_addr: addr = 192.168.1.100;
	local ipv6_addr: addr = [::ffff:c0a8:164]; # IPv4-mapped IPv6 address

	print ipv4_addr;
	print ipv6_addr;
	}
