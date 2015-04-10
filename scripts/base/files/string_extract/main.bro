@load base/frameworks/files

module FileStringExtract;

export {

	## The default max size, in bytes, for extracted string content.
	## A value of zero means unlimited.
	const default_limit = 0 &redef;

	redef record Files::AnalyzerArgs += {
		## The maximum allowed string size in bytes
		## Once reached, a :bro:see:`file_string_extraction_limit` event is
		## raised and the analyzer will be removed unless
		## :bro:see:`FileStringExtract::set_limit` is called to increase the
		## limit.  A value of zero means "no limit".
		string_extract_limit: count &default=default_limit;

		## The pattern which preceded the string content to extract.
		string_extract_preamble: string &optional;

		## The pattern which comes after the string content to extract.
		string_extract_postamble: string &optional;

		## An event to callback with the content of extracted strings.
		string_extract_event: event(f: fa_file, data: string) &optional;
	};
}
