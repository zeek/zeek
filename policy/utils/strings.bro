##! Functions to assist with small string analysis and manipulation that can
##! be implemented as Bro functions and don't need to be implemented as built 
##! in functions.

## Returns true if the given string is at least 25% composed of 8-bit
## characters.
function is_string_binary(s: string): bool
	{
	return byte_len(gsub(s, /[\x00-\x7f]/, "")) * 100 / |s| >= 25;
	}

## Takes a :bro:type:`set[string]` and joins each element together with the 
## second argument.
function join_string_set(ss: set[string], j: string): string
	{
	local output="";
	local i=0;
	for ( s in ss )
		{
		if ( i > 0 )
			output = cat(output, j);
			
		output = cat(output, s);
		++i;
		}
	return output;
	}
