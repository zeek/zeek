# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff zeek/.stderr
# @TEST-EXEC: btest-diff zeek/.stdout

@TEST-START-FILE configfile
mycolors Red,asdf,Blue
nocolors 
color_vec Green
bad_color_vec Green,1234,Blue
no_color_vec 
@TEST-END-FILE

@load base/frameworks/config

redef exit_only_after_terminate=T;

type Color: enum { Red, Green, Blue, };

option mycolors = set(Red, Green);
option nocolors = set(Red, Green);

option color_vec: vector of Color = { Red };
option bad_color_vec: vector of Color = { Red };
option no_color_vec: vector of Color = { Red };

event zeek_init()
	{
	Config::read_config("../configfile");
	}

event Input::end_of_data(name: string, source:string)
	{
	print mycolors;
	print nocolors;
	print color_vec;
	print bad_color_vec;
	print no_color_vec;
	terminate();
	}
