# @TEST-SERIALIZE: comm

# @TEST-EXEC: btest-bg-run broproc bro %INPUT
# @TEST-EXEC: btest-bg-wait -k 5
# @TEST-EXEC: btest-diff broproc/intel.log

@TEST-START-FILE intel.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
1.2.3.4	Intel::ADDR	source1	this host is just plain baaad	http://some-data-distributor.com/1234
1.2.3.4	Intel::ADDR	source1	this host is just plain baaad	http://some-data-distributor.com/1234
e@mail.com	Intel::EMAIL	source1	Phishing email source	http://some-data-distributor.com/100000
@TEST-END-FILE

@load frameworks/communication/listen

redef Intel::read_files += { "../intel.dat" };
redef enum Intel::Where += { SOMEWHERE };

event do_it()
	{
	Intel::seen([$indicator="e@mail.com",
	             $indicator_type=Intel::EMAIL,
	             $where=SOMEWHERE]);

	Intel::seen([$host=1.2.3.4,
	             $where=SOMEWHERE]);
	}

global log_lines = 0;
event Intel::log_intel(rec: Intel::Info)
	{
	++log_lines;
	if ( log_lines == 2 )
		terminate();
	}

event bro_init() &priority=-10
	{
	schedule 1sec { do_it() };
	}
