# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff zeek/.stderr
# @TEST-EXEC: btest-diff zeek/.stdout

@TEST-START-FILE configfile
mycolors Red,asdf,Blue
nocolors 
@TEST-END-FILE

@load base/frameworks/config

type Color: enum { Red, Green, Blue, };

option mycolors = set(Red, Green);
option nocolors = set(Red, Green);

event zeek_init()
	{ Config::read_config("../configfile"); }

event Input::end_of_data(name: string, source:string)
	{
	print mycolors;
	print nocolors;
	terminate();
	}
