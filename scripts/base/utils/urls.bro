##! Functions for URL handling.

## A regular expression for matching and extracting URLs.
const url_regex = /^([a-zA-Z\-]{3,5})(:\/\/[^\/?#"'\r\n><]*)([^?#"'\r\n><]*)([^[:blank:]\r\n"'><]*|\??[^"'\r\n><]*)/ &redef;

type URI: record {
	scheme:		string &optional;
	# this could be a domain name or an IP address
	netlocation:	string;
	portnum:	count &optional;
	path:		string &optional;
	file_name:	string &optional;
	file_ext:	string &optional;
	params_k:	table[count] of string;
	params_v:	table[count] of string;
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
	local u: uri = [$netlocation=""];

        if ( /\?/ in s)
                {
                local k: table[count] of string;
                local v: table[count] of string;
                u$params_k = k;
                u$params_v = v;

                parts = split1(s, /\?/);
                s = parts[1];
                local query: string = parts[2];
                if (/&/ in query)
                        {
                        local opv: table[count] of string = split(query, /&/);

                        for (each in opv)
                                {
                                if (/=/ in opv[each])
                                        {
                                        parts = split1(opv[each], /=/);

                                        u$params_k[each] = parts[1];
                                        u$params_v[each] = parts[2];
                                        }
                                }
                        }
                else
                        {
                        parts = split1(query, /=/);
                        u$params_k[0] = parts[1];
                        u$params_v[0] = parts[2];
                        }
                }
	if (/:\/\// in s)
		{
		parts = split1(s, /:\/\//);
		u$protocol = parts[1];
		s = parts[2];
		}
	if (/\// in s)
		{
		parts = split1(s, /\//);
		s = parts[1];
		u$path = fmt("/%s", parts[2]);
		
		if (|u$path| > 1)
			{
			local last_token: string = find_last(u$path, /\/.+/);
			local full_filename = split1(last_token, /\//)[2];
			if (/\./ in full_filename)
				{
				u$file_name = split1(full_filename, /\./)[1];
				u$file_ext = split1(full_filename, /\./)[2];
				u$path = subst_string(u$path, fmt("%s.%s", u$file_name, u$file_ext), "");
				}
			else
				{
				u$file_name = full_filename;
				u$path = subst_string(u$path, u$file_name, "");
				}
			}
		}
	if (/:/ in s)
		{
		parts = split1(s, /:/);
		u$netlocation = parts[1];
		u$portnum = to_count(parts[2]);
		}
	else
		{
		u$netlocation = s;
		}
	return u;
	}
