##! Functions to assist with small string analysis and manipulation that can
##! be implemented as Zeek functions and don't need to be implemented as built-in
##! functions.

## Returns true if the given string is at least 25% composed of 8-bit
## characters.
function is_string_binary(s: string): bool
	{
	return |gsub(s, /[\x00-\x7f]/, "")| * 100 / |s| >= 25;
	}

## Given a string, returns an escaped version.
##
## s: a string to escape.
##
## chars: a string containing all the characters that need to be escaped.
##
## Returns: a string with all occurrences of any character in *chars* escaped
##          using ``\``, and any literal ``\`` characters likewise escaped.
function string_escape(s: string, chars: string): string
	{
	s = subst_string(s, "\\", "\\\\");
	for ( c in chars )
		s = subst_string(s, c, cat("\\", c));
	return s;
	}

## Cut a number of characters from the end of the given string.
##
## s: a string to trim.
##
## tail_len: the number of characters to remove from the end of the string.
##
## Returns: the given string with *tail_len* characters removed from the end.
function cut_tail(s: string, tail_len: count): string
	{
	if ( tail_len > |s| )
		tail_len = |s|;
	return sub_bytes(s, 1, int_to_count(|s| - tail_len));
	}
