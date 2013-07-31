@load ./addrs

## This function can be used to generate a consistent filename for when
## contents of a file, stream, or connection are being extracted to disk.
function generate_extraction_filename(prefix: string, c: connection, suffix: string): string
	{
	local conn_info = fmt("%s:%d-%s:%d", addr_to_uri(c$id$orig_h), c$id$orig_p,
	                      addr_to_uri(c$id$resp_h), c$id$resp_p);

	if ( prefix != "" )
		conn_info = fmt("%s_%s", prefix, conn_info);
	if ( suffix != "" )
		conn_info = fmt("%s_%s", conn_info, suffix);

	return conn_info;
	}

## For CONTENT-DISPOSITION headers, this function can be used to extract
## the filename.
function extract_filename_from_content_disposition(data: string): string
	{
	local filename = sub(data, /^.*[nN][aA][mM][eE][[:blank:]]*\*?=[[:blank:]]*/, "");

	# Remove quotes around the filename if they are there.
	if ( /^\"/ in filename )
		filename = split_n(filename, /\"/, F, 2)[2];

	# Remove the language and encoding if it's there.
	if ( /^[a-zA-Z0-9\!#$%&+-^_`{}~]+'[a-zA-Z0-9\!#$%&+-^_`{}~]*'/ in filename )
		filename = sub(filename, /^.+'.*'/, "");

	return unescape_URI(filename);
	}
