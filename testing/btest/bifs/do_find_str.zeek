#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = "this is the concatenation of HTTP fields of the fOrM of the website that I am protecting";
	local b = "form";
	local c = "FORM";
	local d = "FoRm";
	local e = "om0";
	local f = "f0rm";
	local g = "fOrm";
	local h = "fOrM";


	print "insensitive";
	print find_str(a, b, 0, -1, F);
	print find_str(a, c, 0, -1, F);
	print find_str(a, d, 0, -1, F);
	print find_str(a, e, 0, -1, F);
	print find_str(a, f, 0, -1, F);
	print find_str(a, g, 0, -1, F);
	print find_str(a, h, 0, -1, F);
	print "sensitive";
	print find_str(a, b, 0, -1);
	print find_str(a, c, 0, -1);
	print find_str(a, d, 0, -1);
	print find_str(a, e, 0, -1);
	print find_str(a, f, 0, -1);
	print find_str(a, g, 0, -1);
	print find_str(a, h, 0, -1);
	}
