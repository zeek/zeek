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

function check_member(s: subnet)
	{
	if ( s in testt )
		print fmt("in says: %s is member", s);
	else
		print fmt("in says: %s is no member", s);

	if ( check_subnet(s, testt) )
		print fmt("check_subnet says: %s is member", s);
	else
		print fmt("check_subnet says: %s is no member", s);

	}

event zeek_init()
	{
	check_member(10.2.0.2/32);
	check_member(10.2.0.2/31);
	check_member(10.6.0.0/9);
	check_member(10.2.0.0/8);
	}
