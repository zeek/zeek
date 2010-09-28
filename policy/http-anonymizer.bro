# $Id:$

# We can't do HTTP rewriting unless we process everything in the connection.
@load http-reply
@load http-entity
@load http-anon-server
@load http-anon-useragent
@load http-anon-utils
@load http-abstract

@load anon

module HTTP;

redef rewriting_http_trace = T;
redef http_entity_data_delivery_size = 18874368;
redef abstract_max_length = 18874368;

const rewrite_header_in_position = F;

const http_response_reasons = {
	"no content", "ok", "moved permanently", "not modified",
	"use local copy", "object not found", "forbidden", "okay",
	"object moved", "found", "http", "redirecting to main server",
	"internal server error", "not found", "unauthorized", "moved",
	"redirected", "continue", "access forbidden", "partial content",
	"redirect", "<empty>", "authorization required",
	"request time-out", "moved temporarily", "",
};

const keep_alive_pat = /(([0-9]+|timeout=[0-9]+|max=[0-9]+),?)*/ ;

const content_type =
	  /video\/(x-flv)(;)?/ 	# video
	| /audio\/(x-scpls)/
	| /image\/(gif|bmp|jpeg|pjpeg|tiff|png|x-icon)(;)?(qs\=[0-9](\.[0-9])?)?,?/
	| /application\/(octet-stream|x-www-form-urlencoded|x-javascript|rss\+xml|x-gzip|x-ns-proxy-autoconfig|pdf|pkix-crl|x-shockwave-flash|postscript|xml|rdf\+xml|excel|msword|x-wais-source)(;)?(charset=(iso-8859-1|iso8859-1|gb2312|windows-1251|windows-1252|utf-8))?/
	| /text\/(plain|js|html|\*|css|xml|javascript);?(charset=(iso-8859-1|iso8859-1|gb2312|windows-1251|windows-1252|utf-8))?/
	| /^unknown$/
	;

const accept_enc_pat =
	/(((x-)?deflate|(x-)?compress|\*|identity|(x-)?gzip|bzip|bzip2)(\; *q\=[0-9](\.[0-9])?)?,?)*/ ;
const accept_charset_pat =
	/((windows-(1252|1251)|big5|iso-8859-(1|15)|\*|utf-(8|16))(\; *q\=[0-9](\.[0-9])?)?,?)*/ ;
const connection_pat = /((close|keep\-alive|transfer\-encoding|te),?)*/ ;

const http_methods =
	/get|put|post|head|propfind|connect|options|proppatch|lock|unlock|move|delete|mkcol/ ;

const http_version = /(1\.0|1\.1)/ ;

const last_modified_pat =
	  /(Sun|Mon|Tue|Wed|Thu|Fri|Sat), [0-9]+ (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9][0-9][0-9][0-9] .*/
	| /(-)?[0-9]+/
	;

const vary_pat =
	/((\*| *|accept|accept\-charset|negotiate|host|user\-agent|accept\-language|accept\-encoding|cookie),?)*/ ;

const accept_lang_pat =
	/(( *|tw|cs|mx|tr|ru|sk|au|hn|sv|no|bg|en|ko|kr|ca|pl|nz|fr|ch|jo|gb|zh|hk|cn|lv|de|nl|dk|fi|nl|es|pe|it|pt|br|ve|cl|ja|jp|he|ha|ar|us|en-us|da)(\; *q\=[0-9](\.[0-9]+)?)?(,|-|\_)?)*/ ;

const accept_pat =
	/(( *|audio|application|\*|gif|xml|xhtml\+xml|x-rgb|x-xbm|video|x-gsarcade-launch|mpeg|sgml|tiff|x-rgb|x-xbm|postscript|text|html|x-xbitmap|pjpeg|vnd.ms-powerpoint|vnd.ms-excel|msword|salt\+html|xhtml|plain|jpeg|jpg|x-shockwave-flash|x-|css|image|png|\*)(\; *q\=[0-9]*(\.[0-9]+)?)?(,|\/|\+)?)*/ ;

const tcn_pat = /list|choice|adhoc|re-choose|keep/;

const date_pat =
	  /(sun|mon|tue|wed|thu|fri|sat)\,*[0-9]+ *(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec) *[0-9]+ ([0-9]+:)*[0-9]+ gmt/
	| /(sun|mon|tue|wed|thu|fri|sat)*(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec) *[0-9]+ *([0-9]+:)*[0-9]+(am|pm)?( *[0-9]+)?( *gmt)?/ ;

const content_encoding_pat = /gzip|deflate|x-compress|x-gzip/;

const hashed_headers =
	  /COOKIE/
	| /AUTHOR/
	| /CACHE-CONTROL/
	| /ETAG/
	| /VIA/
	| /X-VIA/
	| /IISEXPORT/
	| /SET-COOKIE/
	| /X-JUNK/
	| /PRAGMA/
	| /AUTHORIZATION/
	| /X-POWERED-BY/
	| /X-CACHE/
	| /X-FORWARDED-FOR/
	| /X-PAD/
	| /X-C/
	| /XSERVER/
	| /FROM/
	| /CONTENT-DISPOSITION/
	| /X-ASPNET-VERSION/
	| /GUID/
	| /REGIONDATA/
	| /CLIENTID/
	| /X-CACHE-HEADERS-SET-BY/
	| /X-CACHE-LOOKUP/
	| /WARNING/
	| /MICROSOFTOFFICEWEBSERVER/
	| /IF-NONE-MATCH/
	| /X-AMZ-ID-[0-9]/
	| /X-N/
	| /X-TR/
	| /X-RSN/
	#| /X-POOKIE/	# these are weird ... next two are from slashdot
	#| /X-FRY/
	#| /X-BENDER/
	| /RANGE/
	| /IF-RANGE/
	| /CONTENT-RANGE/
	| /AD-REACH/
	| /HMSERVER/
	| /STATUS/
	| /X-SERVED/
	| /WWW-AUTHENTICATE/
	| /X-RESPONDING-SERVER/
	| /MAX-AGE/
	| /POST-CHECK/
	| /PRE-CHECK/
	| /X-CONTENT-ENCODED-BY/
	| /X-USER-IP/
	| /X-ICAP-VERSION/
	| /X-DELPHI/
	| /AUTHENTICATION-INFO/
	| /PPSERVER/
	| /EDGE-CONTROL/
	| /COMPRESSION-CONTROL/
	| /CONTENT-MD5/
	| /X-HOST/
	| /P3P/
	;

event http_request(c: connection, method: string,
		   original_URI: string, unescaped_URI: string, version: string)
	{
	if (! rewriting_trace() )
		return;

	print http_anon_log,
		fmt(" > %s %s %s ", method, original_URI, version);

	if ( to_lower(method) != http_methods )
		{
		print http_anon_log, fmt("*** Unknown method %s", method);
		method = string_cat(" (anon-unknown) ", anonymize_string(method));
		}

	original_URI = anonymize_http_URI(original_URI);

	if ( version != http_version )
		{
		print http_anon_log, fmt("*** Unknown version %s ", version);
		version = string_cat(" (anon-unknown) ", anonymize_string(version));
		}

	print http_anon_log, fmt(" < %s %s %s ", method, original_URI, version);

	rewrite_http_request(c, method, original_URI, version);
	}

event http_reply(c: connection, version: string, code: count, reason: string)
	{
	if ( rewriting_trace() )
		{
		reason = to_lower(strip(reason));
		if ( reason !in http_response_reasons )
			{
			print http_anon_log,
				fmt("*** Unknown reply reason %s ", reason);
			rewrite_http_reply(c, version, code,
				anonymize_string(reason));
			}
		else
			rewrite_http_reply(c, version, code, reason);
		}
	}

function check_pat(value: string, pat: pattern, name: string): string
	{
	if ( value == pat )
		return value;

	print http_anon_log, fmt("*** invalid %s: %s", name, value);
	return "(anon-unknown): ";
	}

function check_pat2(value: string, pat: pattern, name: string): string
	{
	if ( value == pat )
		return value;

	print http_anon_log, fmt("*** invalid %s: %s", name, value);
	return fmt("(anon-unknown): %s", anonymize_string(value));
	}

function check_pat3(value: string, pat: pattern): string
	{
	if ( value == pat )
		return value;

	return fmt("(anon-unknown): %s", anonymize_string(value));
	}

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( ! rewriting_trace() )
		return;

	# Only rewrite top-level headers.
	local s = lookup_http_request_stream(c);
	local msg = get_http_message(s, is_orig);

	if ( msg$entity_level != 1 )
		return;

	value = strip(value);

	if ( name == "CONTENT-LENGTH" )
		{
		# if ( rewrite_header_in_position )
		# {
		#     local p = current_packet(c);
		#     if ( p$is_orig == is_orig )
		#     {
		#         # local s = lookup_http_request_stream(c);
		#         # local msg = get_http_message(s, is_orig);
		#         if ( msg$header_slot == 0 )
		#             msg$header_slot = reserve_rewrite_slot(c);
		#     }
		#     else
		#         print fmt("cannot reserve a slot at %.6f", network_time());
		# }
		print http_anon_log,
			fmt("X-Original-Content-Length: %s --", value);
		name = "X-Original-Content-Length";
		}

	else if ( name == "TRANSFER-ENCODING" || name == "TE" )
		{
		print http_anon_log, fmt("TRANSFER-ENCOODING: %s --", value);
		name = "X-Original-Transfer-Encoding";
		}

	else if ( name == "HOST" )
		{
		local anon_host = "";

		if ( value == simple_filename )
			anon_host = anonymize_path(value);
		else
			anon_host = anonymize_host(value);

		print http_anon_log, fmt("HOST: %s > %s", value, anon_host);
		value = anon_host;
		}

	else if ( name == "REFERER" )
		{
		local anon_ref = anonymize_http_URI(value);
		print http_anon_log, fmt("REFERER: %s > %s", value, anon_ref);
		value = anon_ref;
		}

	else if ( name == "LOCATION" || name == "CONTENT-LOCATION" )
		value = anonymize_http_URI(value);

	else if ( name == "SERVER" )
		value = filter_in_http_server(to_lower(value));

	else if ( name == "USER-AGENT" )
		value = filter_in_http_useragent(to_lower(value));

	else if ( name == "KEEP-ALIVE" )
		value = check_pat(value, keep_alive_pat, "keep-alive");

	else if ( name == "DATE" || name == "IF-MODIFIED-SINCE" ||
		  name == "UNLESS-MODIFIED-SINCE" )
		value = check_pat2(to_lower(value), date_pat, "date");

	else if ( name == "ACCEPT-CHARSET" )
		value = check_pat(to_lower(value), accept_charset_pat,
					"accept-charset");

	else if ( name == "CONTENT-TYPE" )
		{
		value = check_pat2(to_lower(value), content_type, "content-type");
		# local stream = lookup_http_request_stream(c);
		# local the_http_msg = get_http_message(stream, is_orig);
		# the_http_msg$content_type = value;
		}

	else if ( name == "ACCEPT-ENCODING" )
		value = check_pat2(to_lower(value), accept_enc_pat,
					"accept-encoding");

	else if ( name == "PAGE-COMPLETION-STATUS" )
		value = check_pat2(to_lower(value), /(ab)?normal/,
					"page-completion-status");

	else if ( name == "CONNECTION" || name == "PROXY-CONNECTION" )
		value = check_pat2(to_lower(value), connection_pat,
					"connection type");

	else if ( name == "LAST-MODIFIED" || name == "EXPIRES" )
		value = check_pat(value, last_modified_pat, name);

	else if (name == "ACCEPT-LANGUAGE" || name == "LANGUAGE")
		value = check_pat2(to_lower(value), accept_lang_pat,
					"accept-language");

	else if ( name == "ACCEPT" )
		value = check_pat(to_lower(value), accept_pat, "accept");

	else if ( name == "ACCEPT-RANGES" )
		value = check_pat2(to_lower(value), /(bytes|none) */,
					"accept-ranges");

	else if ( name == "MIME-VERSION" )
		value = check_pat3(value, /[0-9]\.[0-9]/);

	else if ( name == "TCN" )
		value = check_pat3(value, tcn_pat);

	else if ( name == "CONTENT-ENCODING" )
		value = check_pat2(value, content_encoding_pat,
					"content-encoding");

	else if ( name == "CONTENT-LANGUAGE" )
		value = check_pat2(value, accept_lang_pat, "content-language");

	else if ( name == "ALLOW" )
		value = check_pat3(value, http_methods);

	else if ( name == "AGE" || name == "BANDWIDTH" )
		value = check_pat3(value, /[0-9]+/);

	else if ( name == "VARY" )
		value = check_pat2(value, vary_pat, "vary");

	else if ( name == hashed_headers )
		value = anonymize_string(value);

	else
		{
		print http_anon_log, fmt("unknown header: %s : %s", name, value);
		value = string_cat("(anon-unknown): ", anonymize_string(value));
		}

	rewrite_http_header(c, is_orig, name, value);
	}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
	{
	if ( ! rewriting_trace() )
		return;

	if ( rewrite_header_in_position )
		{
		local p = current_packet(c);
		if ( p$is_orig == is_orig )
			{
			local s = lookup_http_request_stream(c);
			local msg = get_http_message(s, is_orig);
			if ( msg$header_slot == 0 )
				msg$header_slot = reserve_rewrite_slot(c);
			}
		else
			print fmt("cannot reserve a slot at %.6f", network_time());

		# An empty line to mark the end of headers.
		rewrite_http_data(c, is_orig, "\r\n");
		}
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	if ( ! rewriting_trace() )
		return;

	if ( stat$interrupted )
		{
		print http_log,
			fmt("%.6f %s message interrupted at length=%d \"%s\"",
				network_time(), id_string(c$id),
				stat$body_length, stat$finish_msg);
		}

	local s = lookup_http_request_stream(c);
	local msg = get_http_message(s, is_orig);
	if ( msg$header_slot > 0 )
		seek_rewrite_slot(c, msg$header_slot);

	local data_length = 0;
	local data_hash = "";
	local sanitized_abstract = "";

	if ( ! is_orig || stat$body_length > 0 )
		{
		data_length = byte_len(msg$abstract);
		data_hash = anonymize_string(msg$abstract);
		sanitized_abstract = string_fill(data_length, data_hash);

		data_length += stat$content_gap_length;

		rewrite_http_header(c, is_orig, "Content-Length",
					fmt(" %d", data_length));

		rewrite_http_header(c, is_orig, "X-anon-content-hash",
					fmt(" %s", data_hash));

		rewrite_http_header(c, is_orig, "X-Actual-Data-Length",
					fmt(" %d; gap=%d, content-length=%s",
						stat$body_length,
						stat$content_gap_length,
						msg$content_length));
		}

	if ( msg$header_slot > 0 )
		{
		release_rewrite_slot(c, msg$header_slot);
		msg$header_slot = 0;
		}

	if ( ! rewrite_header_in_position )
		# An empty line to mark the end of headers.
		rewrite_http_data(c, is_orig, "\r\n");

	if ( data_length > 0 )
		rewrite_http_data(c, is_orig, sanitized_abstract);
	}
