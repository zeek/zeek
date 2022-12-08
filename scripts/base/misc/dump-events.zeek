##! This script dumps the events that Zeek raises out to standard output in a
##! readable form. This is for debugging only and allows to understand events and
##! their parameters as Zeek processes input.
@load base/frameworks/config

module DumpEvents;

export {
	## If true, output events on stdout.
	option enable = F;

	## If true, include event arguments in output.
	option include_args = T;

	## By default, only events that are handled in a script are dumped. Setting this option to true
	## will cause unhandled events to be dumped too.
	option dump_all_events = F;

	## Only include events matching the given pattern into output. By default, the
	## pattern matches all events.
	option include = /.*/;
}

event zeek_init() &priority=999
	{
	Option::set_change_handler("DumpEvents::enable", function(ID: string, new_value: bool): bool {
		if ( new_value )
			enable_module_events("DumpEvents");
		else
			disable_module_events("DumpEvents");

		return new_value;
	});
	Option::set_change_handler("DumpEvents::dump_all_events", function(ID: string, new_value: bool): bool {
		if ( new_value )
			generate_all_events();
		else
			reset_generate_all_events();

		return new_value;
	});

	Config::set_value("DumpEvents::enable", DumpEvents::enable);
	Config::set_value("DumpEvents::dump_all_events", DumpEvents::dump_all_events);
	}

event new_event(name: string, args: call_argument_vector)
	{
	if ( ! DumpEvents::enable )  # Avoid very early invocations
		return;

	if ( include !in name )
		return;

	print fmt("%17.6f %s", network_time(), name);

	if ( ! include_args || |args| == 0 )
		return;

	for ( i in args )
		{
		local a = args[i];

		local proto = fmt("%s: %s", a$name, a$type_name);

		if ( a?$value )
			print fmt("                  [%d] %-18s = %s", i, proto, a$value);
		else
			print fmt("                  | %-18s = %s [default]", proto, a$value);
		}

	print "";
	}
