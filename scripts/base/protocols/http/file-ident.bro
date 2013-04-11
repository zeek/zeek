##! Identification of file types in HTTP response bodies with file content sniffing.

@load base/frameworks/notice
@load ./main
@load ./utils
@load ./file-analysis

module HTTP;

export {
	redef enum Notice::Type += {
		## Indicates when the file extension doesn't seem to match the file
		## contents.
		Incorrect_File_Type,
	};

	redef record Info += {
		## Mime type of response body identified by content sniffing.
		mime_type:    string   &log &optional;
	};
	
	## Mapping between mime type strings (without character set) and
	## regular expressions for URLs.
	## The :bro:enum:`HTTP::Incorrect_File_Type` notice is generated if the
	## pattern doesn't match the mime type that was discovered.
	const mime_types_extensions: table[string] of pattern = {
		["application/x-dosexec"] = /\.([eE][xX][eE]|[dD][lL][lL])/,
	} &redef;
	
	## A pattern for filtering out :bro:enum:`HTTP::Incorrect_File_Type` urls
	## that are not noteworthy before a notice is created.  Each
	## pattern added should match the complete URL (the matched URLs include
	## "http://" at the beginning).
	const ignored_incorrect_file_type_urls = /^$/ &redef;
}

event file_new(f: fa_file) &priority=5
	{
	if ( ! f?$source ) return;
	if ( f$source != "HTTP" ) return;
	if ( ! f?$mime_type ) return;
	if ( ! f?$conns ) return;

	for ( cid in f$conns )
		{
		local c: connection = f$conns[cid];

		if ( ! c?$http ) next;

		c$http$mime_type = f$mime_type;

		local mime_str: string = split1(f$mime_type, /;/)[1];

		if ( mime_str !in mime_types_extensions ) next;
		if ( ! c$http?$uri ) next;
		if ( mime_types_extensions[mime_str] in c$http$uri ) next;

		local url = build_url_http(c$http);

		if ( url == ignored_incorrect_file_type_urls ) next;

		local message = fmt("%s %s %s", mime_str, c$http$method, url);
		NOTICE([$note=Incorrect_File_Type,
		        $msg=message,
		        $conn=c]);
		}
	}

event file_over_new_connection(f: fa_file, c: connection) &priority=5
	{
	if ( ! f?$source ) return;
	if ( f$source != "HTTP" ) return;
	if ( ! f?$mime_type ) return;
	if ( ! c?$http ) return;

	# Spread the mime around (e.g. for partial content, file_type event only
	# happens once for the first connection, but if there's subsequent
	# connections to transfer the same file, they'll be lacking the mime_type
	# field if we don't do this).
	c$http$mime_type = f$mime_type;
	}

# Tracks byte-range request / partial content response mime types, indexed
# by [connection, uri] pairs.  This is needed because a person can pipeline
# byte-range requests over multiple connections to the same uri.  Without
# the tracking, only the first request in the pipeline for each connection
# would get a mime_type field assigned to it (by the FileAnalysis policy hooks).
global partial_types: table[conn_id, string] of string &read_expire=5mins;

# Priority 4 so that it runs before the handler that will write to http.log.
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	&priority=4
	{
	if ( ! c$http$range_request ) return;
	if ( ! c$http?$uri ) return;

	if ( c$http?$mime_type )
		{
		partial_types[c$id, c$http$uri] = c$http$mime_type;
		return;
		}

	if ( [c$id, c$http$uri] in partial_types )
		c$http$mime_type = partial_types[c$id, c$http$uri];
	}
