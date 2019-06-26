#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = 3.14;
	local b = 2.71;
	local c = -3.14;
	local d = -2.71;

	print floor(a);
	print floor(b);
	print floor(c);
	print floor(d);

	print sqrt(a);

	print exp(a);

	print ln(a);

	print log10(a);
	}
