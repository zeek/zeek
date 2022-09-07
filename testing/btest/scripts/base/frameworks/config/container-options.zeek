# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/frameworks/config

type Color: enum { RED, GREEN, BLUE };

option my_set: set[Color] = set(RED);
option my_vector: vector of Color = vector(RED);
option my_table: table[Color] of string = table([RED] = "red");

event zeek_init()
	{
	print my_set;
	Config::set_value("my_set", set());
	print my_set;
	Config::set_value("my_set", set(BLUE));
	print my_set;
	Config::set_value("my_set", set(RED, GREEN, BLUE));
	print my_set;
	Config::set_value("my_set", set());
	print my_set;

	print "---";

	print my_vector;
	Config::set_value("my_vector", vector());
	print my_vector;
	Config::set_value("my_vector", vector(BLUE));
	print my_vector;
	Config::set_value("my_vector", vector(RED, GREEN, BLUE));
	print my_vector;
	Config::set_value("my_vector", vector());
	print my_vector;

	print "---";

	print my_table;
	Config::set_value("my_table", table());
	print my_table;
	Config::set_value("my_table", table([BLUE] = "blue"));
	print my_table;
	Config::set_value("my_table", table([RED] = "red", [GREEN] = "green", [BLUE] = "blue"));
	print my_table;
	Config::set_value("my_table", table());
	print my_table;
	}

