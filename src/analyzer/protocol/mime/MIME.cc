#include "config.h"

#include "NetVar.h"
#include "MIME.h"
#include "Event.h"
#include "Reporter.h"
#include "digest.h"
#include "file_analysis/Manager.h"

#include "events.bif.h"

// Here are a few things to do:
//
// 1. Add a Bro internal function 'stop_deliver_data_of_entity' so
// that the engine does not decode and deliver further data for the
// entity (which may speed up the engine by avoiding copying).
//
// 2. Better support for structured header fields, in particular,
// headers of form: <name>=<value>; <param_1>=<param_val_1>;
// <param_2>=<param_val_2>; ... (so that

namespace analyzer { namespace mime {

static const data_chunk_t null_data_chunk = { 0, 0 };

int mime_header_only = 0;
int mime_decode_data = 1;
int mime_submit_data = 1;

enum MIME_HEADER_FIELDS {
	MIME_CONTENT_TYPE,
	MIME_CONTENT_TRANSFER_ENCODING,
	MIME_FIELD_OTHER,
};

enum MIME_CONTENT_SUBTYPE {
	CONTENT_SUBTYPE_MIXED,		// for multipart
	CONTENT_SUBTYPE_ALTERNATIVE,	// for multipart
	CONTENT_SUBTYPE_DIGEST,		// for multipart

	CONTENT_SUBTYPE_RFC822,		// for message
	CONTENT_SUBTYPE_PARTIAL,	// for message
	CONTENT_SUBTYPE_EXTERNAL_BODY,	// for message

	CONTENT_SUBTYPE_PLAIN,		// for text

	CONTENT_SUBTYPE_OTHER,
};

enum MIME_CONTENT_ENCODING {
	CONTENT_ENCODING_7BIT,
	CONTENT_ENCODING_8BIT,
	CONTENT_ENCODING_BINARY,
	CONTENT_ENCODING_QUOTED_PRINTABLE,
	CONTENT_ENCODING_BASE64,
	CONTENT_ENCODING_OTHER,
};

enum MIME_BOUNDARY_DELIMITER {
	NOT_MULTIPART_BOUNDARY,
	MULTIPART_BOUNDARY,
	MULTIPART_CLOSING_BOUNDARY,
};

static const char* MIMEHeaderName[] = {
	"content-type",
	"content-transfer-encoding",
	0,
};

static const char* MIMEContentTypeName[] = {
	"MULTIPART",
	"MESSAGE",
	"TEXT",
	0,
};

static const char* MIMEContentSubtypeName[] = {
	"MIXED",		// for multipart
	"ALTERNATIVE",		// for multipart
	"DIGEST",		// for multipart

	"RFC822",		// for message
	"PARTIAL",		// for message
	"EXTERNAL-BODY",	// for message

	"PLAIN",		// for text

	0,			// other
};

static const char* MIMEContentEncodingName[] = {
	"7BIT",
	"8BIT",
	"BINARY",
	"QUOTED-PRINTABLE",
	"BASE64",
	0,
};

int is_null_data_chunk(data_chunk_t b)
	{
	return b.data == 0;
	}

int is_lws(char ch)
	{
	return ch == 9 || ch == 32;
	}

StringVal* new_string_val(int length, const char* data)
	{
	return new StringVal(length, data);
	}

StringVal* new_string_val(const char* data, const char* end_of_data)
	{
	return new StringVal(end_of_data - data, data);
	}

StringVal* new_string_val(const data_chunk_t buf)
	{
	return new_string_val(buf.length, buf.data);
	}

static data_chunk_t get_data_chunk(BroString* s)
	{
	data_chunk_t b;
	b.length = s->Len();
	b.data = (const char*) s->Bytes();
	return b;
	}

int fputs(data_chunk_t b, FILE* fp)
	{
	for ( int i = 0; i < b.length; ++i )
		if ( fputc(b.data[i], fp) == EOF )
			return EOF;
	return 0;
	}

void MIME_Mail::Undelivered(int len)
	{
	// is_orig param not available, doesn't matter as long as it's consistent
	file_mgr->Gap(cur_entity_len, len, analyzer->GetAnalyzerTag(), analyzer->Conn(),
	              false);
	}

int strcasecmp_n(data_chunk_t s, const char* t)
	{
	return ::strcasecmp_n(s.length, s.data, t);
	}

int MIME_count_leading_lws(int len, const char* data)
	{
	int i;
	for ( i = 0; i < len; ++i )
		if ( ! is_lws(data[i]) )
			break;
	return i;
	}

int MIME_count_trailing_lws(int len, const char* data)
	{
	int i;
	for ( i = 0; i < len; ++i )
		if ( ! is_lws(data[len - 1 - i]) )
			break;
	return i;
	}

// See RFC 2822, page 11
int MIME_skip_comments(int len, const char* data)
	{
	if ( len == 0 || data[0] != '(' )
		return 0;

	int par = 0;
	for ( int i = 0; i < len; ++i )
		{
		switch ( data[i] ) {
		case '(':
			++par;
			break;

		case ')':
			--par;
			if ( par == 0 )
				return i + 1;
			break;

		case '\\':
			++i;
			break;
		}
		}

	return len;
	}

// Skip over lws and comments, but not tspecials. Do not use this
// function in quoted-string or comments.
int MIME_skip_lws_comments(int len, const char* data)
	{
	int i = 0;
	while ( i < len )
		{
		if ( is_lws(data[i]) )
			++i;
		else
			{
			if ( data[i] == '(' )
				i += MIME_skip_comments(len - i, data + i);
			else
				return i;
			}
		}

	return len;
	}

int MIME_get_field_name(int len, const char* data, data_chunk_t* name)
	{
	int i = MIME_skip_lws_comments(len, data);
	while ( i < len )
		{
		int j;
		if ( MIME_is_field_name_char(data[i]) )
			{
			name->data = data + i;

			for ( j = i; j < len; ++j )
				if ( ! MIME_is_field_name_char(data[j]) )
					break;

			name->length = j - i;
			return j;
			}

		j = MIME_skip_lws_comments(len - i, data + i);
		i += (j > 0) ? j : 1;
		}

	return -1;
	}

// See RFC 2045, page 12.
int MIME_is_tspecial (char ch)
	{
	return ch == '(' || ch == ')' || ch == '<' || ch == '>' || ch == '@' ||
	       ch == ',' || ch == ';' || ch == ':' || ch == '\\' || ch == '"' ||
	       ch == '/' || ch == '[' || ch == ']' || ch == '?' || ch == '=';
	}

int MIME_is_field_name_char (char ch)
	{
	return ch >= 33 && ch <= 126 && ch != ':';
	}

int MIME_is_token_char (char ch)
	{
	return ch >= 33 && ch <= 126 && ! MIME_is_tspecial(ch);
	}

// See RFC 2045, page 12.
// A token is composed of characters that are not SPACE, CTLs or tspecials
int MIME_get_token(int len, const char* data, data_chunk_t* token)
	{
	int i = MIME_skip_lws_comments(len, data);
	while ( i < len )
		{
		int j;

		if ( MIME_is_token_char(data[i]) )
			{
			token->data = (data + i);
			for ( j = i; j < len; ++j )
				{
				if ( ! MIME_is_token_char(data[j]) )
					break;
				}

			token->length = j - i;
			return j;
			}

		j = MIME_skip_lws_comments(len - i, data + i);
		i += (j > 0) ? j : 1;
		}

	return -1;
	}

int MIME_get_slash_token_pair(int len, const char* data, data_chunk_t* first, data_chunk_t* second)
	{
	int offset;
	const char* data_start = data;

	offset = MIME_get_token(len, data, first);
	if ( offset < 0 )
		{
		// DEBUG_MSG("first token missing in slash token pair");
		return -1;
		}

	data += offset;
	len -= offset;

	offset = MIME_skip_lws_comments(len, data);
	if ( offset < 0 || offset >= len || data[offset] != '/' )
		{
		// DEBUG_MSG("/ not found in slash token pair");
		return -1;
		}

	++offset;
	data += offset;
	len -= offset;

	offset = MIME_get_token(len, data, second);
	if ( offset < 0 )
		{
		// DEBUG_MSG("second token missing in slash token pair");
		return -1;
		}

	data += offset;
	len -= offset;

	return data - data_start;
	}

// See RFC 2822, page 13.
int MIME_get_quoted_string(int len, const char* data, data_chunk_t* str)
	{
	int offset = MIME_skip_lws_comments(len, data);

	len -= offset;
	data += offset;

	if ( len <= 0 || *data != '"' )
		return -1;

	for ( int i = 1; i < len; ++i )
		{
		switch ( data[i] ) {
		case '"':
			str->data = data + 1;
			str->length = i - 1;
			return offset + i + 1;

		case '\\':
			++i;
			break;
		}
		}

	return -1;
	}

int MIME_get_value(int len, const char* data, BroString*& buf)
	{
	int offset = MIME_skip_lws_comments(len, data);

	len -= offset;
	data += offset;

	if ( len > 0 && *data == '"' )
		{
		data_chunk_t str;
		int end = MIME_get_quoted_string(len, data, &str);
		if ( end < 0 )
			return -1;

		buf = MIME_decode_quoted_pairs(str);
		return offset + end;
		}

	else
		{
		data_chunk_t str;
		int end = MIME_get_token(len, data, &str);
		if ( end < 0 )
			return -1;

		buf = new BroString((const u_char*)str.data, str.length, 1);
		return offset + end;
		}
	}

// Decode each quoted-pair: a '\' followed by a character by the
// quoted character. The decoded string is returned.

BroString* MIME_decode_quoted_pairs(data_chunk_t buf)
	{
	const char* data = buf.data;
	char* dest = new char[buf.length+1];
	int j = 0;
	for ( int i = 0; i < buf.length; ++i )
		if ( data[i] == '\\' )
			{
			if ( ++i < buf.length )
				dest[j++] = data[i];
			else
				{
				// a trailing '\' -- don't know what
				// to do with it -- ignore it.
				}
			}
		else
			dest[j++] = data[i];
	dest[j] = 0;

	return new BroString(1, (byte_vec) dest, j);
	}


} } // namespace analyzer::*

using namespace analyzer::mime;

MIME_Multiline::MIME_Multiline()
	{
	line = 0;
	}

MIME_Multiline::~MIME_Multiline()
	{
	delete line;
	delete_strings(buffer);
	}

void MIME_Multiline::append(int len, const char* data)
	{
	buffer.push_back(new BroString((const u_char*) data, len, 1));
	}

BroString* MIME_Multiline::get_concatenated_line()
	{
	if ( buffer.size() == 0 )
		return 0;

	delete line;
	line = concatenate(buffer);

	return line;
	}


MIME_Header::MIME_Header(MIME_Multiline* hl)
	{
	lines = hl;
	name = value = value_token = rest_value = null_data_chunk;

	BroString* s = hl->get_concatenated_line();
	int len = s->Len();
	const char* data = (const char*) s->Bytes();

	int offset = MIME_get_field_name(len, data, &name);
	if ( offset < 0 )
		return;

	len -= offset; data += offset;
	offset = MIME_skip_lws_comments(len, data);

	if ( offset < len && data[offset] == ':' )
		{
		value.length = len - offset - 1;
		value.data = data + offset + 1;
		while ( value.length && isspace(*value.data) )
			{
			--value.length;
			++value.data;
			}
		}
	else
		// malformed header line
		name = null_data_chunk;
	}

MIME_Header::~MIME_Header()
	{
	delete lines;
	}

int MIME_Header::get_first_token()
	{
	if ( MIME_get_token(value.length, value.data, &value_token) >= 0 )
		{
		rest_value.data = value_token.data + value_token.length;
		rest_value.length = value.data + value.length - rest_value.data;
		return 1;
		}
	else
		{
		value_token = rest_value = null_data_chunk;
		return 0;
		}
	}

data_chunk_t MIME_Header::get_value_token()
	{
	if ( ! is_null_data_chunk(value_token) )
		return value_token;
	get_first_token();
	return value_token;
	}

data_chunk_t MIME_Header::get_value_after_token()
	{
	if ( ! is_null_data_chunk(rest_value) )
		return rest_value;
	get_first_token();
	return rest_value;
	}

MIME_Entity::MIME_Entity(MIME_Message* output_message, MIME_Entity* parent_entity)
	{
	init();
	parent = parent_entity;
	message = output_message;
	if ( parent )
		content_encoding = parent->ContentTransferEncoding();
	}

void MIME_Entity::init()
	{
	in_header = 1;
	end_of_data = 0;

	current_header_line = 0;
	current_field_type = MIME_FIELD_OTHER;

	need_to_parse_parameters = 0;

	content_type_str = new StringVal("TEXT");
	content_subtype_str = new StringVal("PLAIN");

	content_encoding_str = 0;
	multipart_boundary = 0;
	content_type = CONTENT_TYPE_TEXT;
	content_subtype = CONTENT_SUBTYPE_PLAIN;
	content_encoding = CONTENT_ENCODING_OTHER;

	parent = 0;
	current_child_entity = 0;

	base64_decoder = 0;

	data_buf_length = 0;
	data_buf_data = 0;
	data_buf_offset = -1;

	message = 0;
	}

MIME_Entity::~MIME_Entity()
	{
	if ( ! end_of_data )
		reporter->AnalyzerError(message ? message->GetAnalyzer() : 0,
		            "missing MIME_Entity::EndOfData() before ~MIME_Entity");

	delete current_header_line;
	Unref(content_type_str);
	Unref(content_subtype_str);
	delete content_encoding_str;
	delete multipart_boundary;

	for ( unsigned int i = 0; i < headers.size(); ++i )
		delete headers[i];
	headers.clear();

	delete base64_decoder;
	}

void MIME_Entity::Deliver(int len, const char* data, int trailing_CRLF)
	{
	if ( in_header )
		{
		if ( len == 0 || *data == '\0' )
			{ // an empty line at the end of header fields
			FinishHeader();
			in_header = 0;
			SubmitAllHeaders();

			// Note: it's possible that we are in the
			// trailer of a chunked transfer (see HTTP.cc).
			// In this case, end_of_data will be set in
			// HTTP_Entity::SubmitAllHeaders(), and we
			// should not begin a new body.

			if ( ! end_of_data )
				BeginBody();
			}

		else if ( is_lws(*data) )
			// linear whitespace - a continuing header line
			ContHeader(len, data);
		else
			NewHeader(len, data);
		}
	else
		{
		if ( ! mime_header_only && data )
			NewDataLine(len, data, trailing_CRLF);
		}
	}

void MIME_Entity::BeginBody()
	{
	if ( content_encoding == CONTENT_ENCODING_BASE64 )
		StartDecodeBase64();

	if ( content_type == CONTENT_TYPE_MESSAGE )
		BeginChildEntity();
	}

void MIME_Entity::EndOfData()
	{
	if ( end_of_data )
		return;

	end_of_data = 1;

	if ( in_header )
		{
		FinishHeader();
		in_header = 0;
		SubmitAllHeaders();
		message->SubmitEvent(MIME_EVENT_ILLEGAL_FORMAT,
					"entity body missing");
		}

	else
		{
		if ( current_child_entity != 0 )
			{
			if ( content_type == CONTENT_TYPE_MULTIPART )
				IllegalFormat("multipart closing boundary delimiter missing");
			EndChildEntity();
			}

		if ( content_encoding == CONTENT_ENCODING_BASE64 )
			FinishDecodeBase64();

		if ( data_buf_offset > 0 )
			{
			SubmitData(data_buf_offset, data_buf_data);
			data_buf_offset = -1;
			}
		}

	message->EndEntity (this);
	}

void MIME_Entity::NewDataLine(int len, const char* data, int trailing_CRLF)
	{
	if ( content_type == CONTENT_TYPE_MULTIPART )
		{
		switch ( CheckBoundaryDelimiter(len, data) ) {
			case MULTIPART_BOUNDARY:
				if ( current_child_entity != 0 )
					EndChildEntity();
				BeginChildEntity();
				return;

			case MULTIPART_CLOSING_BOUNDARY:
				if ( current_child_entity != 0 )
					EndChildEntity();
				EndOfData();
				return;
		}
		}

	if ( content_type == CONTENT_TYPE_MULTIPART ||
	     content_type == CONTENT_TYPE_MESSAGE )
		{
		// Here we ignore the difference among 7bit, 8bit and
		// binary encoding, and thus do not need to decode
		// before passing the data to child.

		if ( current_child_entity != 0 )
			// Data before the first or after the last
			// boundary delimiter are ignored
			current_child_entity->Deliver(len, data, trailing_CRLF);
		}
	else
		{
		if ( mime_decode_data )
			DecodeDataLine(len, data, trailing_CRLF);
		}
	}

void MIME_Entity::NewHeader(int len, const char* data)
	{
	FinishHeader();

	if ( len == 0 )
		return;

	ASSERT(! is_lws(*data));

	current_header_line = new MIME_Multiline();
	current_header_line->append(len, data);
	}

void MIME_Entity::ContHeader(int len, const char* data)
	{
	if ( current_header_line == 0 )
		{
		IllegalFormat("first header line starts with linear whitespace");

		// shall we try it as a new header or simply ignore this line?
		int ws = MIME_count_leading_lws(len, data);
		NewHeader(len - ws, data + ws);
		return;
		}

	current_header_line->append(len, data);
	}

void MIME_Entity::FinishHeader()
	{
	if ( current_header_line == 0 )
		return;

	MIME_Header* h = new MIME_Header(current_header_line);
	current_header_line = 0;

	if ( ! is_null_data_chunk(h->get_name()) )
		{
		ParseMIMEHeader(h);
		SubmitHeader(h);
		headers.push_back(h);
		}
	else
		delete h;
	}

int MIME_Entity::LookupMIMEHeaderName(data_chunk_t name)
	{
	// A linear lookup should be fine for now.
	// header names are case-insensitive (RFC 822, 2822, 2045).

	for ( int i = 0; MIMEHeaderName[i] != 0; ++i )
		if ( strcasecmp_n(name, MIMEHeaderName[i]) == 0 )
			return i;
	return -1;
	}

void MIME_Entity::ParseMIMEHeader(MIME_Header* h)
	{
	if ( h == 0 )
		return;

	current_field_type = LookupMIMEHeaderName(h->get_name());

	switch ( current_field_type ) {
		case MIME_CONTENT_TYPE:
			ParseContentTypeField(h);
			break;

		case MIME_CONTENT_TRANSFER_ENCODING:
			ParseContentEncodingField(h);
			break;
	}
	}

int MIME_Entity::ParseContentTypeField(MIME_Header* h)
	{
	data_chunk_t val = h->get_value();
	int len = val.length;
	const char* data = val.data;

	data_chunk_t ty, subty;
	int offset;

	offset = MIME_get_slash_token_pair(len, data, &ty, &subty);
	if ( offset < 0 )
		{
		IllegalFormat("media type/subtype not found in content type");
		return 0;
		}
	data += offset;
	len -= offset;

	Unref(content_type_str);
	content_type_str = (new StringVal(ty.length, ty.data))->ToUpper();
	Unref(content_subtype_str);
	content_subtype_str = (new StringVal(subty.length, subty.data))->ToUpper();

	ParseContentType(ty, subty);

	// Proceed to parameters.
	if ( need_to_parse_parameters )
		ParseFieldParameters(len, data);

	if ( content_type == CONTENT_TYPE_MULTIPART && ! multipart_boundary )
		{
		IllegalFormat("boundary delimiter is not specified for a multipart entity -- content is treated as type application/octet-stream");
		content_type = CONTENT_TYPE_OTHER;
		content_subtype = CONTENT_SUBTYPE_OTHER;
		}

	return 1;
	}

int MIME_Entity::ParseContentEncodingField(MIME_Header* h)
	{
	data_chunk_t enc;

	enc = h->get_value_token();
	if ( is_null_data_chunk(enc) )
		{
		IllegalFormat("encoding type not found in content encoding");
		return 0;
		}

	content_encoding_str = new BroString((const u_char*)enc.data, enc.length, 1);
	ParseContentEncoding(enc);

	if ( need_to_parse_parameters )
		{
		data_chunk_t val = h->get_value_after_token();
		if ( ! is_null_data_chunk(val) )
			ParseFieldParameters(val.length, val.data);
		}

	return 1;
	}

int MIME_Entity::ParseFieldParameters(int len, const char* data)
	{
	data_chunk_t attr;

	while ( 1 )
		{
		int offset = MIME_skip_lws_comments(len, data);
		if ( offset < 0 || offset >= len || data[offset] != ';' )
			break;

		++offset;
		data += offset;
		len -= offset;

		offset = MIME_get_token(len, data, &attr);
		if ( offset < 0 )
			{
			IllegalFormat("attribute name not found in parameter specification");
			return 0;
			}

		data += offset;
		len -= offset;

		offset = MIME_skip_lws_comments(len, data);
		if ( offset < 0 || offset >= len || data[offset] != '=' )
			{
			IllegalFormat("= not found in parameter specification");
			continue;
			}

		++offset;
		data += offset;
		len -= offset;

		BroString* val = 0;
		// token or quoted-string
		offset = MIME_get_value(len, data, val);
		if ( offset < 0 )
			{
			IllegalFormat("value not found in parameter specification");
			delete val;
			continue;
			}

		data += offset;
		len -= offset;

		ParseParameter(attr, get_data_chunk(val));
		delete val;
		}

	return 1;
	}

void MIME_Entity::ParseContentType(data_chunk_t type, data_chunk_t sub_type)
	{
	int i;
	for ( i = 0; MIMEContentTypeName[i]; ++i )
		if ( strcasecmp_n(type, MIMEContentTypeName[i]) == 0 )
			break;

	content_type = i;

	for ( i = 0; MIMEContentSubtypeName[i]; ++i )
		if ( strcasecmp_n(sub_type, MIMEContentSubtypeName[i]) == 0 )
			break;

	content_subtype = i;

	switch ( content_type ) {
		case CONTENT_TYPE_MULTIPART:
		case CONTENT_TYPE_MESSAGE:
			need_to_parse_parameters = 1;
			break;

		default:
			need_to_parse_parameters = 0;
			break;
	}
	}

void MIME_Entity::ParseContentEncoding(data_chunk_t encoding_mechanism)
	{
	int i;
	for ( i = 0; MIMEContentEncodingName[i]; ++i )
		if ( strcasecmp_n(encoding_mechanism,
					MIMEContentEncodingName[i]) == 0 )
			break;

	content_encoding = i;
	}

void MIME_Entity::ParseParameter(data_chunk_t attr, data_chunk_t val)
	{
	switch ( current_field_type ) {
		case MIME_CONTENT_TYPE:
			if ( content_type == CONTENT_TYPE_MULTIPART &&
			     strcasecmp_n(attr, "boundary") == 0 )
				multipart_boundary = new BroString((const u_char*)val.data, val.length, 1);
			break;

		case MIME_CONTENT_TRANSFER_ENCODING:
			break;

		default:
			break;
	}
	}


int MIME_Entity::CheckBoundaryDelimiter(int len, const char* data)
	{
	if ( ! multipart_boundary )
		{
		reporter->Warning("boundary delimiter was not specified for a multipart message\n");
		DEBUG_MSG("headers of the MIME entity for debug:\n");
		DebugPrintHeaders();
		return NOT_MULTIPART_BOUNDARY;
		}

	if ( len >= 2 && data[0] == '-' && data[1] == '-' )
		{
		len -= 2; data += 2;

		data_chunk_t delim = get_data_chunk(multipart_boundary);

		int i;
		for ( i = 0; i < len && i < delim.length; ++i )
			if ( data[i] != delim.data[i] )
				return NOT_MULTIPART_BOUNDARY;

		if ( i < delim.length )
			return NOT_MULTIPART_BOUNDARY;

		len -= i;
		data += i;

		if ( len >= 2 && data[0] == '-' && data[1] == '-' )
			return MULTIPART_CLOSING_BOUNDARY;
		else
			return MULTIPART_BOUNDARY;
		}

	return NOT_MULTIPART_BOUNDARY;
	}


// trailing_CRLF indicates whether an implicit CRLF sequence follows data
// (the CRLF sequence is not included in data).

void MIME_Entity::DecodeDataLine(int len, const char* data, int trailing_CRLF)
	{
	if ( ! mime_submit_data )
		return;

	switch ( content_encoding ) {
		case CONTENT_ENCODING_QUOTED_PRINTABLE:
			DecodeQuotedPrintable(len, data);
			break;

		case CONTENT_ENCODING_BASE64:
			DecodeBase64(len, data);
			break;

		case CONTENT_ENCODING_7BIT:
		case CONTENT_ENCODING_8BIT:
		case CONTENT_ENCODING_BINARY:
		case CONTENT_ENCODING_OTHER:
			DecodeBinary(len, data, trailing_CRLF);
			break;
	}
	}

void MIME_Entity::DecodeBinary(int len, const char* data, int trailing_CRLF)
	{
	DataOctets(len, data);

	if ( trailing_CRLF )
		{
		DataOctet(CR);
		DataOctet(LF);
		}
	}

void MIME_Entity::DecodeQuotedPrintable(int len, const char* data)
	{
	// Ignore trailing HT and SP.
	int i;
	for ( i = len - 1; i >= 0; --i )
		if ( data[i] != HT && data[i] != SP )
			break;

	int end_of_line = i;
	int soft_line_break = 0;

	for ( i = 0; i <= end_of_line; ++i )
		{
		if ( data[i] == '=' )
			{
			if ( i == end_of_line )
				soft_line_break = 1;
			else
				{
				int legal = 0;
				if ( i + 2 < len )
					{
					int a, b;
					a = decode_hex(data[i+1]);
					b = decode_hex(data[i+2]);

					if ( a >= 0 && b >= 0 )
						{
						DataOctet((a << 4) + b);
						legal = 1;
						}
					}

				if ( ! legal )
					{
					// Follows suggestions for a robust
					// decoder. See RFC 2045 page 22.
					IllegalEncoding("= is not followed by two hexadecimal digits in quoted-printable encoding");
					DataOctet(data[i]);
					}
				}
			}

		else if ( (data[i] >= 33 && data[i] <= 60) ||
			   // except controls, whitespace and '='
			  (data[i] >= 62 && data[i] <= 126) )
			DataOctet(data[i]);

		else if ( data[i] == HT || data[i] == SP )
			DataOctet(data[i]);

		else
			{
			IllegalEncoding(fmt("control characters in quoted-printable encoding: %d", (int) (data[i])));
			DataOctet(data[i]);
			}
		}

	if ( ! soft_line_break )
		{
		DataOctet(CR);
		DataOctet(LF);
		}
	}

void MIME_Entity::DecodeBase64(int len, const char* data)
	{
	int rlen;
	char rbuf[128];

	while ( len > 0 )
		{
		rlen = 128;
		char* prbuf = rbuf;
		int decoded = base64_decoder->Decode(len, data, &rlen, &prbuf);
		DataOctets(rlen, rbuf);
		len -= decoded; data += decoded;
		}
	}

void MIME_Entity::StartDecodeBase64()
	{
	if ( base64_decoder )
		{
		reporter->InternalWarning("previous MIME Base64 decoder not released");
		delete base64_decoder;
		}

	base64_decoder = new Base64Converter(message->GetAnalyzer());
	}

void MIME_Entity::FinishDecodeBase64()
	{
	if ( ! base64_decoder )
		return;

	int rlen = 128;
	char rbuf[128];
	char* prbuf = rbuf;

	if ( base64_decoder->Done(&rlen, &prbuf) )
		{ // some remaining data
		if ( rlen > 0 )
			DataOctets(rlen, rbuf);
		}

	delete base64_decoder;
	base64_decoder = 0;
	}

int MIME_Entity::GetDataBuffer()
	{
	int ret = message->RequestBuffer(&data_buf_length, &data_buf_data);
	if ( ! ret || data_buf_length == 0 || data_buf_data == 0 )
		{
		// reporter->InternalError("cannot get data buffer from MIME_Message", "");
		return 0;
		}

	data_buf_offset = 0;
	return 1;
	}

void MIME_Entity::DataOctet(char ch)
	{
	if ( data_buf_offset < 0 && ! GetDataBuffer() )
		return;

	data_buf_data[data_buf_offset] = ch;

	++data_buf_offset;
	if ( data_buf_offset == data_buf_length )
		{
		SubmitData(data_buf_length, data_buf_data);
		data_buf_offset = -1;
		}
	}

void MIME_Entity::SubmitData(int len, const char* buf)
	{
	message->SubmitData(len, buf);
	}

void MIME_Entity::DataOctets(int len, const char* data)
	{
	while ( len > 0 )
		{
		if ( data_buf_offset < 0 && ! GetDataBuffer() )
			return;

		int n = min(data_buf_length - data_buf_offset, len);
		memcpy(data_buf_data + data_buf_offset, data, n);
		data += n;
		data_buf_offset += n;
		len -= n;

		if ( data_buf_offset == data_buf_length )
			{
			SubmitData(data_buf_length, data_buf_data);
			data_buf_offset = -1;
			}
		}
	}

void MIME_Entity::SubmitHeader(MIME_Header* h)
	{
	message->SubmitHeader(h);
	}

void MIME_Entity::SubmitAllHeaders()
	{
	message->SubmitAllHeaders(headers);
	}

void MIME_Entity::BeginChildEntity()
	{
	ASSERT(current_child_entity == 0);
	current_child_entity = NewChildEntity();
	message->BeginEntity(current_child_entity);
	}

void MIME_Entity::EndChildEntity()
	{
	ASSERT(current_child_entity != 0);

	current_child_entity->EndOfData();
	delete current_child_entity;
	current_child_entity = 0;
	}

void MIME_Entity::IllegalFormat(const char* explanation)
	{
	message->SubmitEvent(MIME_EVENT_ILLEGAL_FORMAT, explanation);
	}

void MIME_Entity::IllegalEncoding(const char* explanation)
	{
	message->SubmitEvent(MIME_EVENT_ILLEGAL_ENCODING, explanation);
	}

void MIME_Entity::DebugPrintHeaders()
	{
#ifdef DEBUG_BRO
	for ( unsigned int i = 0; i < headers.size(); ++i )
		{
		MIME_Header* h = headers[i];

		DEBUG_fputs(h->get_name(), stderr);
		DEBUG_MSG(":\"");
		DEBUG_fputs(h->get_value(), stderr);
		DEBUG_MSG("\"\n");
		}
#endif
	}

RecordVal* MIME_Message::BuildHeaderVal(MIME_Header* h)
	{
	RecordVal* header_record = new RecordVal(mime_header_rec);
	header_record->Assign(0, new_string_val(h->get_name())->ToUpper());
	header_record->Assign(1, new_string_val(h->get_value()));
	return header_record;
	}

TableVal* MIME_Message::BuildHeaderTable(MIME_HeaderList& hlist)
	{
	TableVal* t = new TableVal(mime_header_list);

	for ( unsigned int i = 0; i < hlist.size(); ++i )
		{
		Val* index = new Val(i+1, TYPE_COUNT);	// index starting from 1

		MIME_Header* h = hlist[i];
		RecordVal* header_record = BuildHeaderVal(h);

		t->Assign(index, header_record);

		Unref(index);
		}

	return t;
	}

MIME_Mail::MIME_Mail(analyzer::Analyzer* mail_analyzer, int buf_size)
    : MIME_Message(mail_analyzer), md5_hash()
	{
	analyzer = mail_analyzer;

	min_overlap_length = mime_segment_overlap_length;
	max_chunk_length = mime_segment_length;
	int length = buf_size;

	if ( min_overlap_length < 0 )
		min_overlap_length = 0;

	if ( max_chunk_length < min_overlap_length + 32 )
		max_chunk_length = min_overlap_length + 32;

	if ( length < max_chunk_length )
		length = max_chunk_length;

	buffer_start = data_start = 0;
	data_buffer = new BroString(1, new u_char[length+1], length);

	if ( mime_content_hash )
		{
		compute_content_hash = 1;
		md5_init(&md5_hash);
		}
	else
		compute_content_hash = 0;

	content_hash_length = 0;

	top_level = new MIME_Entity(this, 0);	// to be changed to MIME_Mail
	BeginEntity(top_level);
	}

void MIME_Mail::Done()
	{
	top_level->EndOfData();

	SubmitAllData();

	if ( compute_content_hash && mime_content_hash )
		{
		u_char* digest = new u_char[16];
		md5_final(&md5_hash, digest);

		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(content_hash_length, TYPE_COUNT));
		vl->append(new StringVal(new BroString(1, digest, 16)));
		analyzer->ConnectionEvent(mime_content_hash, vl);
		}

	MIME_Message::Done();

	file_mgr->EndOfFile(analyzer->GetAnalyzerTag(), analyzer->Conn());
	}

MIME_Mail::~MIME_Mail()
	{
	delete_strings(all_content);
	delete data_buffer;
	delete top_level;
	}

void MIME_Mail::BeginEntity(MIME_Entity* /* entity */)
	{
	cur_entity_len = 0;

	if ( mime_begin_entity )
		{
		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		analyzer->ConnectionEvent(mime_begin_entity, vl);
		}

	buffer_start = data_start = 0;
	ASSERT(entity_content.size() == 0);
	}

void MIME_Mail::EndEntity(MIME_Entity* /* entity */)
	{
	if ( mime_entity_data )
		{
		BroString* s = concatenate(entity_content);

		val_list* vl = new val_list();
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(s->Len(), TYPE_COUNT));
		vl->append(new StringVal(s));

		analyzer->ConnectionEvent(mime_entity_data, vl);

		if ( ! mime_all_data )
			delete_strings(entity_content);
		else
			entity_content.clear();
		}

	if ( mime_end_entity )
		{
		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		analyzer->ConnectionEvent(mime_end_entity, vl);
		}

	file_mgr->EndOfFile(analyzer->GetAnalyzerTag(), analyzer->Conn());
	}

void MIME_Mail::SubmitHeader(MIME_Header* h)
	{
	if ( mime_one_header )
		{
		val_list* vl = new val_list();
		vl->append(analyzer->BuildConnVal());
		vl->append(BuildHeaderVal(h));
		analyzer->ConnectionEvent(mime_one_header, vl);
		}
	}

void MIME_Mail::SubmitAllHeaders(MIME_HeaderList& hlist)
	{
	if ( mime_all_headers )
		{
		val_list* vl = new val_list();
		vl->append(analyzer->BuildConnVal());
		vl->append(BuildHeaderTable(hlist));
		analyzer->ConnectionEvent(mime_all_headers, vl);
		}
	}

void MIME_Mail::SubmitData(int len, const char* buf)
	{
	if ( buf != (char*) data_buffer->Bytes() + buffer_start )
		{
		reporter->AnalyzerError(GetAnalyzer(),
		                                "MIME buffer misalignment");
		return;
		}

	if ( compute_content_hash )
		{
		content_hash_length += len;
		md5_update(&md5_hash, (const u_char*) buf, len);
		}

	if ( mime_entity_data || mime_all_data )
		{
		BroString* s = new BroString((const u_char*) buf, len, 0);

		if ( mime_entity_data )
			entity_content.push_back(s);
		if ( mime_all_data )
			all_content.push_back(s);
		}

	if ( mime_segment_data )
		{
		const char* data = (char*) data_buffer->Bytes() + data_start;
		int data_len = (buf + len) - data;

		val_list* vl = new val_list();
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(data_len, TYPE_COUNT));
		vl->append(new StringVal(data_len, data));
		analyzer->ConnectionEvent(mime_segment_data, vl);
		}

	// is_orig param not available, doesn't matter as long as it's consistent
	file_mgr->DataIn(reinterpret_cast<const u_char*>(buf), len,
	                 analyzer->GetAnalyzerTag(), analyzer->Conn(), false);

	cur_entity_len += len;
	buffer_start = (buf + len) - (char*)data_buffer->Bytes();
	}

int MIME_Mail::RequestBuffer(int* plen, char** pbuf)
	{
	data_start = buffer_start - min_overlap_length;
	if ( data_start < 0 )
		data_start = 0;

	int overlap = buffer_start - data_start;
	int buffer_end = data_start + max_chunk_length;
	if ( buffer_end > data_buffer->Len() )
		{
		// Copy every thing in [data_start, buffer_start) to
		// [0, overlap).
		if ( buffer_start > data_start )
			memcpy(data_buffer->Bytes(),
				data_buffer->Bytes() + data_start, overlap);
		data_start = 0;
		buffer_start = overlap;
		}

	*plen = max_chunk_length - overlap;
	*pbuf = (char*) data_buffer->Bytes() + buffer_start;

	return 1;
	}

void MIME_Mail::SubmitAllData()
	{
	if ( mime_all_data )
		{
		BroString* s = concatenate(all_content);
		delete_strings(all_content);

		val_list* vl = new val_list();
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(s->Len(), TYPE_COUNT));
		vl->append(new StringVal(s));

		analyzer->ConnectionEvent(mime_all_data, vl);
		}
	}

void MIME_Mail::SubmitEvent(int event_type, const char* detail)
	{
	const char* category = "";

	switch ( event_type ) {
		case MIME_EVENT_ILLEGAL_FORMAT:
			category = "illegal format";
			break;

		case MIME_EVENT_ILLEGAL_ENCODING:
			category = "illegal encoding";
			break;

		default:
			reporter->AnalyzerError(GetAnalyzer(),
			                                "unrecognized MIME_Mail event");
			return;
	}

	if ( mime_event )
		{
		val_list* vl = new val_list();
		vl->append(analyzer->BuildConnVal());
		vl->append(new StringVal(category));
		vl->append(new StringVal(detail));
		analyzer->ConnectionEvent(mime_event, vl);
		}
	}
