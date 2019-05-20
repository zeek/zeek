# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

type blah: string &deprecated;

global my_event: event(arg: string) &deprecated;

global my_hook: hook(arg: string) &deprecated;

type my_record: record {
	a: count &default = 1;
	b: string &optional &deprecated;
};

type my_enum: enum {
	RED,
	GREEN &deprecated,
	BLUE &deprecated
};

type my_other_enum: enum {
	ZERO = 0,
	ONE = 1 &deprecated,
	TWO = 2 &deprecated
};

event zeek_init()
	{
	print ZERO;
	print ONE;
	print TWO;
	print RED;
	print GREEN;
	print BLUE;

	local l: blah = "testing";

	local ls: string = " test";

	event my_event("generate my_event please");
	schedule 1sec { my_event("schedule my_event please") };
	hook my_hook("generate my_hook please");

	local mr = my_record($a = 3, $b = "yeah");
	mr = [$a = 4, $b = "ye"];
	mr = record($a = 5, $b = "y");

	if ( ! mr?$b )
		mr$b = "nooooooo";

	mr$a = 2;
	mr$b = "noooo";
	}

event my_event(arg: string)
	{
	print arg;
	}

hook my_hook(arg: string)
	{
	print arg;
	}

function hmm(b: blah)
	{
	print b;
	}

global dont_use_me: function() &deprecated;

function dont_use_me()
	{
	dont_use_me();
	}

function dont_use_me_either() &deprecated
	{
	dont_use_me_either();
	}
