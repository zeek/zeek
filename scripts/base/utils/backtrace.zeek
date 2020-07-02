## Prints a Zeek function call stack.
##
## show_args: whether to print function argument names/types/values.
##
## one_line: whether to print the stack in a single line or multiple.
##
## one_line_delim: delimiter between stack elements if printing to one line.
##
## skip: the number of call stack elements to skip past, starting from zero,
##       with that being the call to this function.
##
## to_file: the file to which the call stack will be printed.
##
## .. zeek:see:: backtrace
function print_backtrace(show_args: bool &default=F,
                         one_line: bool &default=F,
                         one_line_delim: string &default="|",
                         skip: count &default=1,
                         to_file: file &default=open("/dev/stdout"))
	{
	local bt = backtrace();
	local vs: vector of string = vector();
	local orig_skip = skip;

	for ( i in bt )
		{
		if ( skip > 0 )
			{
			--skip;
			next;
			}

		local bte = bt[i];

		local info = fmt("%s(", bte$function_name);

		if ( show_args )
			for ( ai in bte$function_args )
				{
				local arg = bte$function_args[ai];

				if ( ai > 0 )
					info += ", ";

				info += fmt("%s: %s", arg$name, arg$type_name);

				if ( arg?$value )
					info += fmt(" = %s", arg$value);
				}

		info += ")";

		if ( bte?$file_location )
			info += fmt(" at %s:%s", bte$file_location, bte$line_location);

		vs += fmt("#%s: %s", i - orig_skip, info);
		}

	if ( one_line )
		{
		local line = "";

		for ( vsi in vs )
			{
			line += one_line_delim + " " + vs[vsi] + " ";

			if ( vsi == |vs| - 1 )
				line += one_line_delim;
			}

		print to_file, line;
		}
	else
		{
		for ( vsi in vs )
			print to_file, vs[vsi];
		}
	}
