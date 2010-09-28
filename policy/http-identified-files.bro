# $Id:$
#
# Analyze HTTP entities for sensitive types (e.g., executables).
#
# Contributed by Seth Hall.

@load http-reply

module HTTP;

const http_identified_log = open_log_file("http-id");

export {
	# Base the libmagic analysis on this many bytes.  Currently,
	# we will in fact use fewer (basically, just what's in the
	# first data packet).
	const magic_content_limit = 1024 &redef;

	# These MIME types are logged and generate a Notice.  The patterns
	# need to match the entire description as returned by libMagic.
	# For example, for plain text it can return
	# "text/plain charset=us-ascii", so you might want to use
	# /text\/plain.*/.
	const watched_mime_types =
		  /application\/x-dosexec/	# Windows and DOS executables
		| /application\/x-executable/	# *NIX executable binary
	&redef;

	const watched_descriptions = /PHP script text/ &redef;

	# URLs included here are not logged and notices are not generated.
	# Take care when defining patterns to not be overly broad.
	const ignored_urls =
		/^http:\/\/www\.download\.windowsupdate\.com\// &redef;

	redef enum Notice += {
		# Generated when we see a MIME type we flagged for watching.
		HTTP_WatchedMIMEType,

		# Generated when the file extension doesn't match
		# the file contents.
		HTTP_IncorrectFileType,
	};

	# Create patterns that *should* be in the URLs for specific MIME types.
	# Notices are generated if the pattern doesn't match.
	const mime_types_extensions = {
		["application/x-dosexec"] = /\.([eE][xX][eE]|[dD][lL][lL])/,
	} &redef;
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
	if ( is_orig )
		# For now we only inspect server responses.
		return;

	local s = lookup_http_request_stream(c);
	local msg = get_http_message(s, is_orig);

@ifndef	( content_truncation_limit )
	# This is only done if http-body.bro is not loaded.
	msg$data_length = msg$data_length + length;
@endif

	# For the time being, we'll just use the data from the first packet.
	# Don't continue until we have enough data.
	# if ( msg$data_length < magic_content_limit )
	#	return;

	# Right now, only try this for the first chunk of data
	if ( msg$data_length > length )
		return;

	local abstract = sub_bytes(data, 1, magic_content_limit);
	local magic_mime = identify_data(abstract, T);
	local magic_descr = identify_data(abstract, F);

	if ( (magic_mime == watched_mime_types ||
	      watched_descriptions in magic_descr) &&
	     s$first_pending_request in s$requests )
		{
		local r = s$requests[s$first_pending_request];
		local host = (s$next_request$host=="") ?
			fmt("%s", c$id$resp_h) : s$next_request$host;

		event file_transferred(c, abstract, magic_descr, magic_mime);

		local url = fmt("http://%s%s", host, r$URI);
		if ( ignored_urls in url )
			return;

		local file_type = "";
		if ( magic_mime == watched_mime_types )
			file_type = magic_mime;
		else
			file_type = magic_descr;

		local message = fmt("%s %s %s %s",
				id_string(c$id), file_type, r$method, url);

		NOTICE([$note=HTTP_WatchedMIMEType, $msg=message, $conn=c,
			$method=r$method, $URL=url]);

		print http_identified_log, fmt("%.06f %s %s",
			network_time(), s$id, message);

		if ( (magic_mime in mime_types_extensions &&
		      mime_types_extensions[magic_mime] !in url) ||
		     (magic_descr in mime_types_extensions &&
		      mime_types_extensions[magic_descr] !in url) )
			NOTICE([$note=HTTP_IncorrectFileType, $msg=message,
				$conn=c, $method=r$method, $URL=url]);
		}
	}
