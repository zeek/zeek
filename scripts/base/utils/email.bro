## Extract mail addresses out of address specifications conforming to RFC5322.
##
## str: A string potentially containing email addresses.
##
## Returns: A vector of extracted email addresses.  An empty vector is returned
##          if no email addresses are discovered.
function extract_email_addrs_vec(str: string): string_vec
	{
	local addrs: vector of string = vector();

	local raw_addrs = find_all(str, /(^|[<,:[:blank:]])[^<,:[:blank:]@]+"@"[^>,;[:blank:]]+([>,;[:blank:]]|$)/);
	for ( raw_addr in raw_addrs )
		addrs[|addrs|] = gsub(raw_addr, /[<>,:;[:blank:]]/, "");

	return addrs;
	}

## Extract mail addresses out of address specifications conforming to RFC5322.
##
## str: A string potentially containing email addresses.
##
## Returns: A set of extracted email addresses.  An empty set is returned 
##          if no email addresses are discovered.
function extract_email_addrs_set(str: string): set[string]
	{
	local addrs: set[string] = set();

	local raw_addrs = find_all(str, /(^|[<,:[:blank:]])[^<,:[:blank:]@]+"@"[^>,;[:blank:]]+([>,;[:blank:]]|$)/);
	for ( raw_addr in raw_addrs )
		add addrs[gsub(raw_addr, /[<>,:;[:blank:]]/, "")];

	return addrs;
	}

## Extract the first email address from a string.
##
## str: A string potentially containing email addresses.
##
## Returns: An email address or empty string if none found.
function extract_first_email_addr(str: string): string
	{
	local addrs = extract_email_addrs_vec(str);
	if ( |addrs| > 0 )
		return addrs[0];
	else
		return "";
	}