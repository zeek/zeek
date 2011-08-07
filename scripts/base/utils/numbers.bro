## Extract the first integer found in the given string.
## If no integer can be found, 0 is returned.
function extract_count(s: string): count
	{
	local parts = split_n(s, /[0-9]+/, T, 1);
	if ( 2 in parts )
		return to_count(parts[2]);
	else
		return 0;
	}