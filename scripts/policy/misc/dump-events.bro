##! This script dumps the events that Bro raises out to standard output in a
##! readable form. This is for debugging only and allows to understand events and
##! their parameters as Bro processes input. Note that it will show only events
##! for which a handler is defined.

module DumpEvents;

export {
	## If true, include event arguments in output.
	const include_args = T &redef;

	## Only include events matching the given pattern into output. By default, the
	## pattern matches all events.
	const include = /.*/ &redef;
}

event new_event(name: string, args: call_argument_vector)
	{
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
