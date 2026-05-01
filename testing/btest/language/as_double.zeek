#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = 1 usec;
	print a as double;
	local b = 1sec;
	print b as double;
	local c = -1min;
	print c as double;
	local d = 1hrs;
	print d as double;
	local e = 1 day;
	print e as double;

	local f = current_time();
	print f as double;

	local g = 0;
	print g as double;
	local h = 10000;
	print h as double;
	local i = -41;
	print i as double;

	print "40" ?as double;
	print "forty" ?as double;
	}
