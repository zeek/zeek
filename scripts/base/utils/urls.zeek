##! Functions for URL handling.

## A regular expression for matching and extracting URLs.
## This is the @imme_emosol regex from https://mathiasbynens.be/demo/url-regex, adapted for Zeek. It's
## not perfect for all of their test cases, but it's one of the shorter ones that covers most of the
## test cases.
const url_regex = /^([a-zA-Z\-]{3,5}):\/\/(-\.)?([^[:blank:]\/?\.#-]+\.?)+(\/[^[:blank:]]*)?/ &redef;

## A URI, as parsed by :zeek:id:`decompose_uri`.
type URI: record {
	## The URL's scheme..
	scheme:       string &optional;
	## The location, which could be a domain name or an IP address. Left empty if not
	## specified.
	netlocation:  string;
	## Port number, if included in URI.
	portnum:      count &optional;
	## Full including the file name. Will be '/' if there's not path given.
	path:         string;
	## Full file name, including extension, if there is a file name.
	file_name:    string &optional;
	## The base filename, without extension, if there is a file name.
	file_base:    string &optional;
	## The filename's extension, if there is a file name.
	file_ext:     string &optional;
	## A table of all query parameters, mapping their keys to values, if there's a
	## query.
	params:       table[string] of string &optional;
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

function decompose_uri(uri: string): URI
	{
	local parts: string_vec;
	local u = URI($netlocation="", $path="/");
	local s = uri;

	if ( /\?/ in s )
		{
		u$params = table();

		parts = split_string1(s, /\?/);
		s = parts[0];
		local query = parts[1];

		if ( /&/ in query )
			{
			local opv = split_string(query, /&/);

			for ( each in opv )
				{
				if ( /=/ in opv[each] )
					{
					parts = split_string1(opv[each], /=/);
					u$params[parts[0]] = parts[1];
					}
				}
			}
		else if ( /=/ in query )
			{
			parts = split_string1(query, /=/);
			u$params[parts[0]] = parts[1];
			}
		}

	if ( /:\/\// in s )
		{
		# Parse scheme and remove from s.
		parts = split_string1(s, /:\/\//);
		u$scheme = parts[0];
		s = parts[1];
		}

	if ( /\// in s )
		{
		# Parse path and remove from s.
		parts = split_string1(s, /\//);
		s = parts[0];
		u$path = fmt("/%s", parts[1]);

		if ( |u$path| > 1 && u$path[|u$path| - 1] != "/" )
			{
			local last_token = find_last(u$path, /\/.+/);
			local full_filename = split_string1(last_token, /\//)[1];

			if ( /\./ in full_filename )
				{
				u$file_name = full_filename;
				u$file_base = split_string1(full_filename, /\./)[0];
				u$file_ext  = split_string1(full_filename, /\./)[1];
				}
			else
				{
				u$file_name = full_filename;
				u$file_base = full_filename;
				}
			}
		}

	if ( /:[0-9]*$/ in s )
		{
		# Input ends with a numeric port or just colon: Strip it
		# for netlocation and convert any port digits into portnum.
		u$netlocation = gsub(s, /:[0-9]*$/, "");
		local portstr = s[|u$netlocation| + 1:];
		if ( portstr != "" )
			u$portnum = to_count(portstr);
		}
	else
		{
		u$netlocation = s;
		}

	return u;
	}
