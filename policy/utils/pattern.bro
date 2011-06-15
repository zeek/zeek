##! Functions for creating and working with patterns.

## This function only works at or before init time.  Given a pattern as a string
## with two tildes (~~) contained in it, it will return a pattern with the
## set[string] elements OR'd together where the double-tilde was given.
## If a literal backslash is include in 'pat', it needs to be given as a double
## backslash due to Bro's string parsing reducing it to a single backslash
## upon rendering.
function set_to_regex(ss: set[string], pat: string): pattern
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

type PatternMatchResult: record {
	## T if a match was found, F otherwise.
	matched: bool;
	## Portion of string that first matched.
	str: string;
	## 1-based offset where match starts.
	off: count;
};

## Matches the given pattern against the given string, returning
## a :bro:type:`PatternMatchResult` record.
## For example:
##     match_pattern("foobar", /o*[a-k]/)
## returns:
##     [matched=T, str=f, off=1]
## because the *first* match is for zero o's followed by an [a-k],
## while:
##     match_pattern("foobar", /o+[a-k]/)
## returns:
##     [matched=T, str=oob, off=2]
function match_pattern(s: string, p: pattern): PatternMatchResult
	{
	local a = split_n(s, p, T, 1);

	if ( |a| == 1 )
		# no match
		return [$matched = F, $str = "", $off = 0];
	else
		return [$matched = T, $str = a[2], $off = |a[1]| + 1];
	}
