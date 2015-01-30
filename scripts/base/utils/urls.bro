##! Functions for URL handling.

## A regular expression for matching and extracting URLs.
const url_regex = /^([a-zA-Z\-]{3,5})(:\/\/[^\/?#"'\r\n><]*)([^?#"'\r\n><]*)([^[:blank:]\r\n"'><]*|\??[^"'\r\n><]*)/ &redef;

## A URI, as parsed by :bro:id:`decompose_uri`.
type URI: record {
	## The URL's scheme..
	scheme:		string &optional;
	## The location, which could be a domain name or an IP address. Left empty if not
	## specified.
	netlocation:	string;
	## Port number, if included in URI.
	portnum:	count &optional;
	## Full including the file name. Will be '/' if there's not path given.
	path:		string;
	## Full file name, including extension, if there is a file name.
	file_name:	string &optional;
	## The base filename, without extension, if there is a file name.
	file_base:	string &optional;
	## The filename's extension, if there is a file name.
	file_ext:	string &optional;
	## A table of all query parameters, mapping their keys to values, if there's a
	## query.
	params:	table[string] of string &optional;
};

## Extracts URLs discovered in arbitrary text.
function find_all_urls(s: string): string_set
	{
	return find_all(s, url_regex);
	}

## Extracts URLs discovered in arbitrary text without
## the URL scheme included.
function find_all_urls_without_scheme(s: string): string_set
	{
	local urls = find_all_urls(s);
	local return_urls: set[string] = set();
	for ( url in urls )
		{
		local no_scheme = sub(url, /^([a-zA-Z\-]{3,5})(:\/\/)/, "");
		add return_urls[no_scheme];
		}

	return return_urls;
	}

function decompose_uri(s: string): URI
	{
	local parts: string_array;
	local u: URI = [$netlocation="", $path="/"];

	if ( /\?/ in s)
		{
		# Parse query.
		u$params = table();

		parts = split1(s, /\?/);
		s = parts[1];
		local query: string = parts[2];

		if ( /&/ in query )
			{
			local opv: table[count] of string = split(query, /&/);

			for ( each in opv )
				{
				if ( /=/ in opv[each] )
					{
					parts = split1(opv[each], /=/);
					u$params[parts[1]] = parts[2];
					}
				}
			}
		else
			{
			parts = split1(query, /=/);
			u$params[parts[1]] = parts[2];
			}
		}

	if ( /:\/\// in s )
		{
		# Parse scheme and remove from s.
		parts = split1(s, /:\/\//);
		u$scheme = parts[1];
		s = parts[2];
		}

	if ( /\// in s )
		{
		# Parse path and remove from s.
		parts = split1(s, /\//);
		s = parts[1];
		u$path = fmt("/%s", parts[2]);

		if ( |u$path| > 1 && u$path[|u$path| - 1] != "/" )
			{
			local last_token: string = find_last(u$path, /\/.+/);
			local full_filename = split1(last_token, /\//)[2];

			if ( /\./ in full_filename )
				{
				u$file_name = full_filename;
				u$file_base = split1(full_filename, /\./)[1];
				u$file_ext = split1(full_filename, /\./)[2];
				}
			else
				{
				u$file_name = full_filename;
				u$file_base = full_filename;
				}
			}
		}

	if ( /:/ in s )
		{
		# Parse location and port.
		parts = split1(s, /:/);
		u$netlocation = parts[1];
		u$portnum = to_count(parts[2]);
		}
	else
		u$netlocation = s;

	return u;
	}
