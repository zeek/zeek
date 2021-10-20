## Extract an integer from a string.
##
## s: The string to search for a number.
##
## get_first: Provide `F` if you would like the last number found.
##
## Returns: The request integer from the given string or 0 if
##          no integer was found.
function extract_count(s: string, get_first: bool &default=T): count
	{
	local extract_num_pattern = /[0-9]+/;
	if ( get_first )
		{
		local first_parts = split_string_n(s, extract_num_pattern, T, 1);
		if ( 1 in first_parts )
			return to_count(first_parts[1]);
		}
	else
		{
		local last_parts = split_string_all(s, extract_num_pattern);
		if ( |last_parts| > 1 )
			return to_count(last_parts[|last_parts|-2]);
		}
	return 0;
	}
