##! Functions for creating patterns.

## This function only works at or before init time.  Given a pattern as a string
## with two tildes (~~) contained in it, it will return a pattern with the
## set[string] elements OR'd together where the double-tilde was given.
## If a literal backslash is include in 'pat', it needs to be given as a double
## backslash due to Bro's string parsing reducing it to a single backslash
## upon rendering.
function build_regex(ss: set[string], pat: string): pattern
	{
	local i: count = 0;
	local return_pat = "";
	for ( s in ss )
		{
		local tmp_pattern = convert_for_pattern(s);
		return_pat = ( i == 0 ) ? 
			 tmp_pattern : cat(tmp_pattern, "|", return_pat);
		++i;
		}
	return string_to_pattern(sub(pat, /~~/, return_pat), F);
	}
