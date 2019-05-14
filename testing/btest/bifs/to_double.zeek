#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = 1 usec;
	print interval_to_double(a);
	local b = 1sec;
	print interval_to_double(b);
	local c = -1min;
	print interval_to_double(c);
	local d = 1hrs;
	print interval_to_double(d);
	local e = 1 day;
	print interval_to_double(e);

	local f = current_time();
	print time_to_double(f);
	}
