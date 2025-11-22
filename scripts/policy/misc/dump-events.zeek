##! This script dumps the events that Zeek raises out to standard output in a
##! readable form. This is for debugging only and allows to understand events and
##! their parameters as Zeek processes input. Note that it will show only events
##! for which a handler is defined.

module DumpEvents;

export {
	## If true, include event arguments in output.
	option include_args = T;

	## By default, only events that are handled in a script are dumped. Setting this option to true
	## will cause unhandled events to be dumped too.
	const dump_all_events = F &redef;

	## Only include events matching the given pattern into output. By default, the
	## pattern matches all events.
	option include = /.*/;

	## Report in JSON format, with one event per line.
	option use_json = F;
}

event zeek_init() &priority=999
	{
	if ( dump_all_events )
		generate_all_events();
	}

event new_event(name: string, args: call_argument_vector)
	{
	if ( include !in name )
		return;

	if ( use_json )
		{
		local j: table[string] of any = {
			["ts"] = network_time(),
			["event"] = name,
		} &ordered;

		if ( include_args && |args| > 0 )
			{
			local j2: table[string] of any = {} &ordered;

			for ( _, arg in args )
				{
				if ( arg?$value )
					j2[arg$name] = arg$value;
				else if ( arg?$default_val )
					j2[arg$name] = arg$default_val;
				}

			j["args"] = j2;
			}

		print to_json(j);
		return;
		}

	print fmt("%17.6f %s", network_time(), name);

	if ( ! include_args || |args| == 0 )
		return;

	for ( i in args )
		{
		local a = args[i];

		local proto = fmt("%s: %s", a$name, a$type_name);

		if ( a?$value )
			print fmt("                  [%d] %-18s = %s", i, proto, a$value);
		else if ( a?$default_val )
			print fmt("                  | %-18s = %s [default]", proto, a$default_val);
		}

	print "";
	}
