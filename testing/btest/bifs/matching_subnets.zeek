# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

global testt: set[subnet] = {
	10.0.0.0/8,
	10.2.0.0/16,
	10.2.0.2/31,
	10.1.0.0/16,
	10.3.0.0/16,
	5.0.0.0/8,
	5.5.0.0/25,
	5.2.0.0/32,
	7.2.0.0/32,
	[2607:f8b0:4008:807::200e]/64,
	[2607:f8b0:4007:807::200e]/64,
	[2607:f8b0:4007:807::200e]/128
};

event zeek_init()
	{
	print testt;
	local c = matching_subnets(10.2.0.2/32, testt);
	print c;
	c = matching_subnets([2607:f8b0:4007:807::200e]/128, testt);
	print c;
	c = matching_subnets(128.0.0.1/32, testt);
	print c;
	c = matching_subnets(10.0.0.2/8, testt);
	print c;
	}
