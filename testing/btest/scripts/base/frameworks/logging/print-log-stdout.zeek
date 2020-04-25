#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff print.log
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff otherfile
# @TEST-EXEC: btest-diff anotherfile

redef Log::print_to_log = Log::REDIRECT_STDOUT;

event zeek_init()
	{
	local f = open("otherfile");
	print f, "hello world ,";
	print "hello world ,";
	print f,2,T;
	print 2,T;
	close(f);
	}

event Log::log_print (rec: Log::PrintLogInfo)
	{
	local f = open("anotherfile");
	print f,"from event",rec;
	close(f);
	}
