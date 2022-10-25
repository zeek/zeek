# @TEST-DOC: Hooks can be annotated with &group and work.
# @TEST-EXEC: zeek %INPUT > output
# @TEST-EXEC: btest-diff output

global the_hook: hook(c: count);

event zeek_init()
{
	hook the_hook(1);
	print "=== disable_event_group(my-group1)";
	disable_event_group("my-group1");
	hook the_hook(2);
}

hook the_hook(c: count)
	{
	print "the_hook without group", c;
	}

hook the_hook(c: count) &group="my-group1"
	{
	print "the_hook with my-group1", c;
	}

hook the_hook(c: count) &group="my-group2"
	{
	print "the_hook with my-group2", c;
	}

hook the_hook(c: count) &group="my-group1" &group="my-group2"
	{
	print "the_hook with my-group1 and my-group2", c;
	}
