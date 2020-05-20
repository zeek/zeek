# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

global testa: set[subnet] = {
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

global testb: table[subnet] of string = {
	[10.0.0.0/8] = "a",
	[10.2.0.0/16] = "b",
	[10.2.0.2/31] = "c",
	[10.1.0.0/16] = "d",
	[10.3.0.0/16] = "e",
	[5.0.0.0/8] = "f",
	[5.5.0.0/25] = "g",
	[5.2.0.0/32] = "h",
	[7.2.0.0/32] = "i",
	[[2607:f8b0:4008:807::200e]/64] = "j",
	[[2607:f8b0:4007:807::200e]/64] = "k",
	[[2607:f8b0:4007:807::200e]/128] = "l"
};


event zeek_init()
	{
	local c = filter_subnet_table(10.2.0.2/32, testa);
	print c;
	c = filter_subnet_table(10.2.0.2/32, testb);
	print c;
	c = filter_subnet_table(10.3.0.2/32, testb);
	print c;
	c = filter_subnet_table(1.0.0.0/8, testb);
	print c;

	local unspecified: table[subnet] of string = table();
	c = filter_subnet_table(10.2.0.2/32, unspecified);
	print c;
	}
