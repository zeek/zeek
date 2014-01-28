##! Functions for URL handling.

## A regular expression for matching and extracting URLs.
const url_regex = /^([a-zA-Z\-]{3,5})(:\/\/[^\/?#"'\r\n><]*)([^?#"'\r\n><]*)([^[:blank:]\r\n"'><]*|\??[^"'\r\n><]*)/ &redef;

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
