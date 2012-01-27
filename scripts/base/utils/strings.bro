##! Functions to assist with small string analysis and manipulation that can
##! be implemented as Bro functions and don't need to be implemented as built 
##! in functions.

## Returns true if the given string is at least 25% composed of 8-bit
## characters.
function is_string_binary(s: string): bool
	{
	return byte_len(gsub(s, /[\x00-\x7f]/, "")) * 100 / |s| >= 25;
	}

## Joins a set of string together, with elements delimited by a constant string.
## ss: a set of strings to join
## j: the string used to join set elements
## Returns: a string composed of the all elements of the set, delimited by the
##          joining string.
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

## Given a string, returns an escaped version.
## s: a string to escape
## chars: a string containing all the characters that need to be escaped
## Returns: a string with all occurrences of any character in ``chars`` escaped
##          using ``\``, and any literal ``\`` characters likewise escaped.
function string_escape(s: string, chars: string): string
	{
	s = subst_string(s, "\\", "\\\\");
	for ( c in chars )
		s = subst_string(s, c, cat("\\", c));
	return s;
	}

## Cut a number of character from the end of the given string.
## s: a string to trim
## tail_len: the number of characters to remove from end of string
## Returns: the string in ``s`` with ``tail_len`` characters removed from end
function cut_tail(s: string, tail_len: count): string
	{
	if ( tail_len > |s| )
		tail_len = |s|;
	return sub_bytes(s, 1, int_to_count(|s| - tail_len));
	}

## Split a string where the delimiter may be escaped. This function is useful
## when splitting strings of the form ``foo,bar\,baz,qux`` with the
## :bro:type:`pattern` ``/,``. While the other split functions would return
## four elements,  ``[foo, bar\, baz, qux]``, this function would respect the
## escape character ``\`` and return only 3 fragments, ``[foo, bar\,baz,
## qux]``, where ``bar\,baz`` represents a single fragment.
##
## str: The input string to split.
##
## delim: The split expression.
##
## esc: The escape sequence.
##
## Returns: A vector of strings where each element is delimited by *delim* in
##          *str*.
##
## .. bro:see:: split split1 split_all split_n str_split
function split_esc(str: string, delim: pattern, esc: pattern): vector of string
    {
    local result: vector of string;

    local s = split_all(str, delim);
    local j = 0;     # Index of the result vector.

    # Tracks whether the previous element was escaped.
    # FIXME: As soon as &default attributes work for vectors, we can get rid of
    # this flag entirely and always use += in the loop below.
    local escaped = F;

    # FIXME: The split* functions should actually return a vector of string,
    # and not a table[count] of string. Once this is fixed, this loop can be
    # rewritten in a more natural way. Now we use the variable ``i`` as actual
    # loop variable.
    local i = 1;
    for ( dummy in s )
        {
        if ( i % 2 != 0 )
            {
            if ( escaped )
                result[j] += s[i];
            else
                result[j] = s[i];

            if ( find_last(s[i], esc && /$/) != "" && i < |s| )
                {
                result[j] += s[i + 1];
                escaped = T;
                }
            else
                {
                ++j;
                if ( escaped )
                    escaped = F;
                }
            }
        ++i;
        }

    return result;
    }
