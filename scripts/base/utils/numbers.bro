## Extract the first integer found in the given string.
## If no integer can be found, 0 is returned.
function extract_count(s: string): count
	{
	local parts = split_string_n(s, /[0-9]+/, T, 1);
	if ( 1 in parts )
		return to_count(parts[1]);
	else
		return 0;
	}
