#include "zeek-config.h"
#include "zeek/analyzer/protocol/mime/MIME.h"

#include "zeek/NetVar.h"
#include "zeek/Base64.h"
#include "zeek/Reporter.h"
#include "zeek/digest.h"
#include "zeek/file_analysis/Manager.h"

#include "analyzer/protocol/mime/events.bif.h"

// Here are a few things to do:
//
// 1. Add a Bro internal function 'stop_deliver_data_of_entity' so
// that the engine does not decode and deliver further data for the
// entity (which may speed up the engine by avoiding copying).
//
// 2. Better support for structured header fields, in particular,
// headers of form: <name>=<value>; <param_1>=<param_val_1>;
// <param_2>=<param_val_2>; ... (so that

namespace zeek::analyzer::mime {

static const data_chunk_t null_data_chunk = { 0, nullptr };

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
	nullptr,
};

static const char* MIMEContentTypeName[] = {
	"MULTIPART",
	"MESSAGE",
	"TEXT",
	nullptr,
};

static const char* MIMEContentSubtypeName[] = {
	"MIXED",		// for multipart
	"ALTERNATIVE",		// for multipart
	"DIGEST",		// for multipart

	"RFC822",		// for message
	"PARTIAL",		// for message
	"EXTERNAL-BODY",	// for message

	"PLAIN",		// for text

	nullptr,			// other
};

static const char* MIMEContentEncodingName[] = {
	"7BIT",
	"8BIT",
	"BINARY",
	"QUOTED-PRINTABLE",
	"BASE64",
	nullptr,
};

bool is_null_data_chunk(data_chunk_t b)
	{
	return b.data == nullptr;
	}

bool is_lws(char ch)
	{
	return ch == 9 || ch == 32;
	}

StringValPtr to_string_val(int length, const char* data)
	{
	return make_intrusive<StringVal>(length, data);
	}

StringValPtr to_string_val(const char* data, const char* end_of_data)
	{
	return make_intrusive<StringVal>(end_of_data - data, data);
	}

StringValPtr to_string_val(const data_chunk_t buf)
	{
	return to_string_val(buf.length, buf.data);
	}

static data_chunk_t get_data_chunk(String* s)
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
	cur_entity_id = file_mgr->Gap(cur_entity_len, len,
	                                    analyzer->GetAnalyzerTag(), analyzer->Conn(),
	                                    is_orig, cur_entity_id);
	}

bool istrequal(data_chunk_t s, const char* t)
	{
	int len = strlen(t);

	if ( s.length != len )
		return false;

	return strncasecmp(s.data, t, len) == 0;
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
static bool  MIME_is_tspecial (char ch, bool is_boundary = false)
	{
	if ( is_boundary )
		return ch == '"';
	else
		return ch == '(' || ch == ')' || ch == '<' || ch == '>' || ch == '@' ||
		       ch == ',' || ch == ';' || ch == ':' || ch == '\\' || ch == '"' ||
		       ch == '/' || ch == '[' || ch == ']' || ch == '?' || ch == '=';
	}

bool MIME_is_field_name_char (char ch)
	{
	return ch >= 33 && ch <= 126 && ch != ':';
	}

static bool MIME_is_token_char (char ch, bool is_boundary = false)
	{
	return ch >= 33 && ch <= 126 && ! MIME_is_tspecial(ch, is_boundary);
	}

// See RFC 2045, page 12.
// A token is composed of characters that are not SPACE, CTLs or tspecials
int MIME_get_token(int len, const char* data, data_chunk_t* token,
                   bool is_boundary)
	{
	int i = 0;

	if ( ! is_boundary )
		i = MIME_skip_lws_comments(len, data);

	while ( i < len )
		{
		int j;

		if ( MIME_is_token_char(data[i], is_boundary) )
			{
			token->data = (data + i);
			for ( j = i; j < len; ++j )
				{
				if ( ! MIME_is_token_char(data[j], is_boundary) )
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

int MIME_get_value(int len, const char* data, String*& buf, bool is_boundary)
	{
	int offset = 0;

	if ( ! is_boundary )	// For boundaries, simply accept everything.
		offset = MIME_skip_lws_comments(len, data);

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
		int end = MIME_get_token(len, data, &str, is_boundary);
		if ( end < 0 )
			return -1;

		buf = new String((const u_char*)str.data, str.length, true);
		return offset + end;
		}
	}

// Decode each quoted-pair: a '\' followed by a character by the
// quoted character. The decoded string is returned.

String* MIME_decode_quoted_pairs(data_chunk_t buf)
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

	return new String(true, (byte_vec) dest, j);
	}

MIME_Multiline::MIME_Multiline()
	{
	line = nullptr;
	}

MIME_Multiline::~MIME_Multiline()
	{
	delete line;
	delete_strings(buffer);
	}

void MIME_Multiline::append(int len, const char* data)
	{
	buffer.push_back(new String((const u_char*) data, len, true));
	}

String* MIME_Multiline::get_concatenated_line()
	{
	if ( buffer.empty() )
		return nullptr;

	delete line;
	line = concatenate(buffer);

	return line;
	}


MIME_Header::MIME_Header(MIME_Multiline* hl)
	{
	lines = hl;
	name = value = value_token = rest_value = null_data_chunk;

	String* s = hl->get_concatenated_line();
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

	want_all_headers = (bool)mime_all_headers;
	}

void MIME_Entity::init()
	{
	in_header = 1;
	end_of_data = 0;

	current_header_line = nullptr;
	current_field_type = MIME_FIELD_OTHER;

	need_to_parse_parameters = 0;

	content_type_str = make_intrusive<StringVal>("TEXT");
	content_subtype_str = make_intrusive<StringVal>("PLAIN");

	content_encoding_str = nullptr;
	multipart_boundary = nullptr;
	content_type = CONTENT_TYPE_TEXT;
	content_subtype = CONTENT_SUBTYPE_PLAIN;
	content_encoding = CONTENT_ENCODING_OTHER;

	parent = nullptr;
	current_child_entity = nullptr;

	base64_decoder = nullptr;

	data_buf_length = 0;
	data_buf_data = nullptr;
	data_buf_offset = -1;

	message = nullptr;
	delay_adding_implicit_CRLF = false;
	want_all_headers = false;
	}

MIME_Entity::~MIME_Entity()
	{
	if ( ! end_of_data )
		reporter->AnalyzerError(message ? message->GetAnalyzer() : nullptr,
		                              "missing MIME_Entity::EndOfData() before ~MIME_Entity");

	delete current_header_line;
	delete content_encoding_str;
	delete multipart_boundary;

	for ( auto& header : headers )
		delete header;
	headers.clear();

	delete base64_decoder;
	}

void MIME_Entity::Deliver(int len, const char* data, bool trailing_CRLF)
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
		if ( current_child_entity != nullptr )
			{
			if ( content_type == CONTENT_TYPE_MULTIPART )
				IllegalFormat("multipart closing boundary delimiter missing");
			EndChildEntity();
			}

		if ( content_encoding == CONTENT_ENCODING_BASE64 )
			FinishDecodeBase64();

		FlushData();
		}

	message->EndEntity (this);
	}

void MIME_Entity::NewDataLine(int len, const char* data, bool trailing_CRLF)
	{
	if ( content_type == CONTENT_TYPE_MULTIPART )
		{
		switch ( CheckBoundaryDelimiter(len, data) ) {
			case MULTIPART_BOUNDARY:
				if ( current_child_entity != nullptr )
					EndChildEntity();
				if ( ! end_of_data )
					BeginChildEntity();
				return;

			case MULTIPART_CLOSING_BOUNDARY:
				if ( current_child_entity != nullptr )
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

		if ( current_child_entity != nullptr )
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
	if ( current_header_line == nullptr )
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
	if ( current_header_line == nullptr )
		return;

	MIME_Header* h = new MIME_Header(current_header_line);
	current_header_line = nullptr;

	if ( ! is_null_data_chunk(h->get_name()) )
		{
		ParseMIMEHeader(h);
		SubmitHeader(h);

		if ( want_all_headers )
			headers.push_back(h);
		else
			delete h;
		}
	else
		delete h;
	}

int MIME_Entity::LookupMIMEHeaderName(data_chunk_t name)
	{
	// A linear lookup should be fine for now.
	// header names are case-insensitive (RFC 822, 2822, 2045).

	for ( int i = 0; MIMEHeaderName[i] != nullptr; ++i )
		if ( istrequal(name, MIMEHeaderName[i]) )
			return i;
	return -1;
	}

void MIME_Entity::ParseMIMEHeader(MIME_Header* h)
	{
	if ( h == nullptr )
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

bool MIME_Entity::ParseContentTypeField(MIME_Header* h)
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
		return false;
		}
	data += offset;
	len -= offset;

	content_type_str = make_intrusive<StringVal>(ty.length, ty.data);
	content_type_str->ToUpper();
	content_subtype_str = make_intrusive<StringVal>(subty.length, subty.data);
	content_subtype_str->ToUpper();

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

	return true;
	}

bool MIME_Entity::ParseContentEncodingField(MIME_Header* h)
	{
	data_chunk_t enc;

	enc = h->get_value_token();
	if ( is_null_data_chunk(enc) )
		{
		IllegalFormat("encoding type not found in content encoding");
		return false;
		}

	delete content_encoding_str;
	content_encoding_str = new String((const u_char*)enc.data, enc.length, true);
	ParseContentEncoding(enc);

	if ( need_to_parse_parameters )
		{
		data_chunk_t val = h->get_value_after_token();
		if ( ! is_null_data_chunk(val) )
			ParseFieldParameters(val.length, val.data);
		}

	return true;
	}

bool MIME_Entity::ParseFieldParameters(int len, const char* data)
	{
	data_chunk_t attr;

	while ( true )
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
			return false;
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

		String* val = nullptr;

		if ( current_field_type == MIME_CONTENT_TYPE &&
		     content_type == CONTENT_TYPE_MULTIPART &&
		     istrequal(attr, "boundary") )
			{
			// token or quoted-string (and some lenience for characters
			// not explicitly allowed by the RFC, but encountered in the wild)
			offset = MIME_get_value(len, data, val, true);

			if ( ! val )
				{
				IllegalFormat("Could not parse multipart boundary");
				continue;
				}

			data_chunk_t vd = get_data_chunk(val);
			delete multipart_boundary;
			multipart_boundary = new String((const u_char*)vd.data,
			                                   vd.length, true);
			}
		else
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
		delete val;
		}

	return true;
	}

void MIME_Entity::ParseContentType(data_chunk_t type, data_chunk_t sub_type)
	{
	int i;
	for ( i = 0; MIMEContentTypeName[i]; ++i )
		if ( istrequal(type, MIMEContentTypeName[i]) )
			break;

	content_type = i;

	for ( i = 0; MIMEContentSubtypeName[i]; ++i )
		if ( istrequal(sub_type, MIMEContentSubtypeName[i]) )
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
		if ( istrequal(encoding_mechanism, MIMEContentEncodingName[i]) )
			break;

	content_encoding = i;
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

void MIME_Entity::DecodeDataLine(int len, const char* data, bool trailing_CRLF)
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
	FlushData();
	}

void MIME_Entity::DecodeBinary(int len, const char* data, bool trailing_CRLF)
	{
	if ( delay_adding_implicit_CRLF )
		{
		delay_adding_implicit_CRLF = false;
		DataOctet(CR);
		DataOctet(LF);
		}

	DataOctets(len, data);

	if ( trailing_CRLF )
		{
		if ( Parent() &&
		     Parent()->MIMEContentType() == mime::CONTENT_TYPE_MULTIPART )
			{
			// For multipart body content, we want to keep all implicit CRLFs
			// except for the last because that one belongs to the multipart
			// boundary delimiter, not the content.  Simply delaying the
			// addition of implicit CRLFs until another chunk of content
			// data comes in is a way to prevent the CRLF before the final
			// message boundary from being accidentally added to the content.
			delay_adding_implicit_CRLF = true;
			}
		else
			{
			DataOctet(CR);
			DataOctet(LF);
			}
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
					a = util::decode_hex(data[i+1]);
					b = util::decode_hex(data[i+2]);

					if ( a >= 0 && b >= 0 )
						{
						DataOctet((a << 4) + b);
						legal = 1;
						i += 2;
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
			IllegalEncoding(util::fmt("control characters in quoted-printable encoding: %d", (int) (data[i])));
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

	analyzer::Analyzer* analyzer = message->GetAnalyzer();

	if ( ! analyzer )
		{
		reporter->InternalWarning("no analyzer associated with MIME message");
		return;
		}

	base64_decoder = new zeek::detail::Base64Converter(analyzer->Conn());
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
	base64_decoder = nullptr;
	}

bool MIME_Entity::GetDataBuffer()
	{
	int ret = message->RequestBuffer(&data_buf_length, &data_buf_data);
	if ( ! ret || data_buf_length == 0 || data_buf_data == nullptr )
		{
		// reporter->InternalError("cannot get data buffer from MIME_Message", "");
		return false;
		}

	data_buf_offset = 0;
	return true;
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

		int n = std::min(data_buf_length - data_buf_offset, len);
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

void MIME_Entity::FlushData()
	{
	if ( data_buf_offset > 0 )
		{
		SubmitData(data_buf_offset, data_buf_data);
		data_buf_offset = -1;
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
	ASSERT(current_child_entity == nullptr);
	current_child_entity = NewChildEntity();
	message->BeginEntity(current_child_entity);
	}

void MIME_Entity::EndChildEntity()
	{
	ASSERT(current_child_entity != nullptr);

	current_child_entity->EndOfData();
	delete current_child_entity;
	current_child_entity = nullptr;
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
	for ( MIME_Header* h : headers )
		{
		DEBUG_fputs(h->get_name(), stderr);
		DEBUG_MSG(":\"");
		DEBUG_fputs(h->get_value(), stderr);
		DEBUG_MSG("\"\n");
		}
#endif
	}

RecordValPtr MIME_Message::ToHeaderVal(MIME_Header* h)
	{
	static auto mime_header_rec = id::find_type<RecordType>("mime_header_rec");
	auto header_record = make_intrusive<RecordVal>(mime_header_rec);
	header_record->Assign(0, to_string_val(h->get_name()));
	auto upper_hn = to_string_val(h->get_name());
	upper_hn->ToUpper();
	header_record->Assign(1, std::move(upper_hn));
	header_record->Assign(2, to_string_val(h->get_value()));
	return header_record;
	}

TableValPtr MIME_Message::ToHeaderTable(MIME_HeaderList& hlist)
	{
	static auto mime_header_list = id::find_type<TableType>("mime_header_list");
	auto t = make_intrusive<TableVal>(mime_header_list);

	for ( size_t i = 0; i < hlist.size(); ++i )
		{
		auto index = val_mgr->Count(i + 1);	// index starting from 1
		MIME_Header* h = hlist[i];
		t->Assign(std::move(index), ToHeaderVal(h));
		}

	return t;
	}

MIME_Mail::MIME_Mail(analyzer::Analyzer* mail_analyzer, bool orig, int buf_size)
: MIME_Message(mail_analyzer), md5_hash()
	{
	analyzer = mail_analyzer;

	min_overlap_length = zeek::detail::mime_segment_overlap_length;
	max_chunk_length = zeek::detail::mime_segment_length;
	is_orig = orig;

	int length = buf_size;

	if ( min_overlap_length < 0 )
		min_overlap_length = 0;

	if ( max_chunk_length < min_overlap_length + 32 )
		max_chunk_length = min_overlap_length + 32;

	if ( length < max_chunk_length )
		length = max_chunk_length;

	buffer_start = data_start = 0;
	data_buffer = new String(true, new u_char[length+1], length);

	if ( mime_content_hash )
		{
		compute_content_hash = 1;
		md5_hash = zeek::detail::hash_init(detail::Hash_MD5);
		}
	else
		compute_content_hash = 0;

	content_hash_length = 0;

	top_level = new MIME_Entity(this, nullptr);	// to be changed to MIME_Mail
	BeginEntity(top_level);
	}

void MIME_Mail::Done()
	{
	top_level->EndOfData();

	SubmitAllData();

	if ( compute_content_hash && mime_content_hash )
		{
		u_char* digest = new u_char[16];
		zeek::detail::hash_final(md5_hash, digest);
		md5_hash = nullptr;

		analyzer->EnqueueConnEvent(mime_content_hash,
			analyzer->ConnVal(),
			val_mgr->Count(content_hash_length),
			make_intrusive<StringVal>(new String(true, digest, 16))
		);
		}

	MIME_Message::Done();

	file_mgr->EndOfFile(analyzer->GetAnalyzerTag(), analyzer->Conn());
	}

MIME_Mail::~MIME_Mail()
	{
	if ( md5_hash )
		EVP_MD_CTX_free(md5_hash);

	delete_strings(all_content);
	delete data_buffer;
	delete top_level;
	}

void MIME_Mail::BeginEntity(MIME_Entity* /* entity */)
	{
	cur_entity_len = 0;
	cur_entity_id.clear();

	if ( mime_begin_entity )
		analyzer->EnqueueConnEvent(mime_begin_entity, analyzer->ConnVal());

	buffer_start = data_start = 0;
	ASSERT(entity_content.size() == 0);
	}

void MIME_Mail::EndEntity(MIME_Entity* /* entity */)
	{
	if ( mime_entity_data )
		{
		String* s = concatenate(entity_content);

		analyzer->EnqueueConnEvent(mime_entity_data,
			analyzer->ConnVal(),
			val_mgr->Count(s->Len()),
			make_intrusive<StringVal>(s)
		);

		if ( ! mime_all_data )
			delete_strings(entity_content);
		else
			entity_content.clear();
		}

	if ( mime_end_entity )
		analyzer->EnqueueConnEvent(mime_end_entity, analyzer->ConnVal());

	file_mgr->EndOfFile(analyzer->GetAnalyzerTag(), analyzer->Conn());
	cur_entity_id.clear();
	}

void MIME_Mail::SubmitHeader(MIME_Header* h)
	{
	if ( mime_one_header )
		analyzer->EnqueueConnEvent(mime_one_header,
			analyzer->ConnVal(),
			ToHeaderVal(h)
		);
	}

void MIME_Mail::SubmitAllHeaders(MIME_HeaderList& hlist)
	{
	if ( mime_all_headers )
		analyzer->EnqueueConnEvent(mime_all_headers,
			analyzer->ConnVal(),
			ToHeaderTable(hlist)
		);
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
		zeek::detail::hash_update(md5_hash, (const u_char*) buf, len);
		}

	if ( mime_entity_data || mime_all_data )
		{
		String* s = new String((const u_char*) buf, len, false);

		if ( mime_entity_data )
			entity_content.push_back(s);
		if ( mime_all_data )
			all_content.push_back(s);
		}

	if ( mime_segment_data )
		{
		const char* data = (char*) data_buffer->Bytes() + data_start;
		int data_len = (buf + len) - data;

		analyzer->EnqueueConnEvent(mime_segment_data,
			analyzer->ConnVal(),
			val_mgr->Count(data_len),
			make_intrusive<StringVal>(data_len, data)
		);
		}

	cur_entity_id = file_mgr->DataIn(
		reinterpret_cast<const u_char*>(buf), len,
		analyzer->GetAnalyzerTag(), analyzer->Conn(), is_orig,
		cur_entity_id);

	cur_entity_len += len;
	buffer_start = (buf + len) - (char*)data_buffer->Bytes();
	}

bool MIME_Mail::RequestBuffer(int* plen, char** pbuf)
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

	return true;
	}

void MIME_Mail::SubmitAllData()
	{
	if ( mime_all_data )
		{
		String* s = concatenate(all_content);
		delete_strings(all_content);

		analyzer->EnqueueConnEvent(mime_all_data,
			analyzer->ConnVal(),
			val_mgr->Count(s->Len()),
			make_intrusive<StringVal>(s)
		);
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
		analyzer->EnqueueConnEvent(mime_event,
			analyzer->ConnVal(),
			make_intrusive<StringVal>(category),
			make_intrusive<StringVal>(detail)
		);
	}

} // namespace zeek::analyzer::mime
