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

## Given a string, returns an escaped version.  This means that
## (1) any occurrences of any character in "chars" are escaped using '\', and
## (2) any '\'s are likewise escaped.
function string_escape(s: string, chars: string): string
	{
	s = subst_string(s, "\\", "\\\\");
	for ( c in chars )
		s = subst_string(s, c, cat("\\", c));
	return s;
	}

## Cut a number of character from the end of the given string.
function cut_tail(s: string, tail_len: count): string
	{
	if ( tail_len > |s| )
		tail_len = |s|;
	return sub_bytes(s, 1, int_to_count(|s| - tail_len));
	}
