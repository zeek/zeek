# $Id:$

enum ExpectBody {
	BODY_EXPECTED,
	BODY_NOT_EXPECTED,
	BODY_MAYBE,
};

enum DeliveryMode {
	UNKNOWN_DELIVERY_MODE,
	CONTENT_LENGTH,
	CHUNKED,
	MULTIPART,
};

##       token          = 1*<any CHAR except CTLs or separators>
##       separators     = "(" | ")" | "<" | ">" | "@"
##                      | "," | ";" | ":" | "\" | <">
##                      | "/" | "[" | "]" | "?" | "="
##                      | "{" | "}" | SP | HT
##      reserved    = ";" | "/" | "?" | ":" | "@" | "&" | "=" | "+" |
##                    "$" | ","

type HTTP_TOKEN	= RE/[^()<>@,;:\\"\/\[\]?={} \t]+/;
type HTTP_WS	= RE/[ \t]*/;
type HTTP_URI	= RE/[[:alnum:][:punct:]]+/;

type HTTP_PDU(is_orig: bool) = case is_orig of {
	true ->		request:	HTTP_Request;
	false ->	reply:		HTTP_Reply;
};

type HTTP_Request = record {
	request:	HTTP_RequestLine;
	msg:		HTTP_Message(BODY_MAYBE);
};

function expect_reply_body(reply_status: int): ExpectBody
	%{
	// TODO: check if the request is "HEAD"
	if ( (reply_status >= 100 && reply_status < 200) ||
	     reply_status == 204 || reply_status == 304 )
		return BODY_NOT_EXPECTED;
	return BODY_EXPECTED;
	%}

type HTTP_Reply = record {
	reply:		HTTP_ReplyLine;
	msg:		HTTP_Message(expect_reply_body(reply.status.stat_num));
};

type HTTP_RequestLine = record {
	method:		HTTP_TOKEN;
	:		HTTP_WS;
	uri:		HTTP_URI;
	:		HTTP_WS;
	version:	HTTP_Version;
} &oneline;

type HTTP_ReplyLine = record {
	version:	HTTP_Version;
	:		HTTP_WS;
	status:		HTTP_Status;
	:		HTTP_WS;
	reason:		bytestring &restofdata;
} &oneline;

type HTTP_Status = record {
	stat_str:	RE/[0-9]{3}/;
} &let {
	stat_num: int = bytestring_to_int(stat_str, 10);
};

type HTTP_Version = record {
	:		"HTTP/";
	vers_str:	RE/[0-9]+\.[0-9]+/;
} &let {
	vers_num: double = bytestring_to_double(vers_str);
};

type HTTP_Headers = HTTP_Header[] &until($input.length() == 0);

type HTTP_Message(expect_body: ExpectBody) = record {
	headers:	HTTP_Headers;
	body_or_not:	case expect_body of {
		BODY_NOT_EXPECTED	-> none:	empty;
		default			-> body:	HTTP_Body(expect_body);
	};
};

# Multi-line headers are supported by allowing header names to be
# empty.
#
type HTTP_HEADER_NAME = RE/|([^: \t]+:)/;
type HTTP_Header = record {
	name:		HTTP_HEADER_NAME &transient;
	:		HTTP_WS;
	value:		bytestring &restofdata &transient;
} &oneline;

type MIME_Line = record {
	line:	bytestring &restofdata &transient;
} &oneline;

type MIME_Lines = MIME_Line[]
	&until($context.flow.is_end_of_multipart($input));

# TODO: parse multipart message according to MIME
type HTTP_Body(expect_body: ExpectBody) =
		case $context.flow.delivery_mode() of {

	CONTENT_LENGTH	-> body: bytestring
				&length = $context.flow.content_length(),
				&chunked;

	CHUNKED		-> chunks: HTTP_Chunks;

	MULTIPART	-> multipart: MIME_Lines;

	default		-> unknown: HTTP_UnknownBody(expect_body);
};

type HTTP_UnknownBody(expect_body: ExpectBody) = case expect_body of {
	BODY_MAYBE, BODY_NOT_EXPECTED	-> maybenot: empty;
	BODY_EXPECTED			-> rest: bytestring &restofflow &chunked;
};

type HTTP_Chunks = record {
	chunks:		HTTP_Chunk[] &until($element.chunk_length == 0);
	headers:	HTTP_Headers;
};

type HTTP_Chunk = record {
	length_line:	bytestring &oneline;
	data:		bytestring &length = chunk_length &chunked;
	opt_crlf:	case chunk_length of {
		0	-> none: empty;
		default	-> crlf: bytestring &oneline &check(trailing_crlf == "");
	};
} &let {
	chunk_length: int = bytestring_to_int(length_line, 16);
};
