#pragma once

#include <assert.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <vector>
#include <queue>

#include "ZeekString.h"
#include "Reporter.h"
#include "analyzer/Analyzer.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(TableVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(StringVal, zeek);
class Base64Converter;

namespace zeek {
using TableValPtr = zeek::IntrusivePtr<TableVal>;
using StringValPtr = zeek::IntrusivePtr<StringVal>;
}

namespace analyzer { namespace mime {

// MIME: Multipurpose Internet Mail Extensions
// Follows RFC 822 & 2822 (Internet Mail), 2045-2049 (MIME)
// See related files: SMTP.h and SMTP.cc

// MIME Constants

#define HT	'\011'
#define SP	'\040'
#define CR	'\015'
#define LF	'\012'

enum MIME_CONTENT_TYPE {
	CONTENT_TYPE_MULTIPART,
	CONTENT_TYPE_MESSAGE,
	CONTENT_TYPE_TEXT,
	CONTENT_TYPE_OTHER,	// image | audio | video | application | <other>
};

enum MIME_EVENT_TYPE {
	MIME_EVENT_ILLEGAL_FORMAT,
	MIME_EVENT_ILLEGAL_ENCODING,
	MIME_EVENT_CONTENT_GAP,
	MIME_EVENT_OTHER,
};



// MIME data structures.

class MIME_Multiline;
class MIME_Header;
class MIME_Body;
class MIME_Entity;	// an "entity" contains headers and a body
class MIME_Mail;
class MIME_Message;

class MIME_Multiline {
public:
	MIME_Multiline();
	~MIME_Multiline();

	void append(int len, const char* data);
	zeek::String* get_concatenated_line();

protected:
	std::vector<const zeek::String*> buffer;
	zeek::String* line;
};

class MIME_Header {
public:
	explicit MIME_Header(MIME_Multiline* hl);
	~MIME_Header();

	zeek::data_chunk_t get_name() const	{ return name; }
	zeek::data_chunk_t get_value() const	{ return value; }

	zeek::data_chunk_t get_value_token();
	zeek::data_chunk_t get_value_after_token();

protected:
	int get_first_token();

	MIME_Multiline* lines;
	zeek::data_chunk_t name;
	zeek::data_chunk_t value;
	zeek::data_chunk_t value_token, rest_value;
};


using MIME_HeaderList = std::vector<MIME_Header*>;

class MIME_Entity {
public:
	MIME_Entity(MIME_Message* output_message, MIME_Entity* parent_entity);
	virtual ~MIME_Entity();

	virtual void Deliver(int len, const char* data, bool trailing_CRLF);
	virtual void EndOfData();

	MIME_Entity* Parent() const { return parent; }
	int MIMEContentType() const { return content_type; }
	[[deprecated("Remove in v4.1.  Use GetContentType().")]]
	zeek::StringVal* ContentType() const { return content_type_str.get(); }
	[[deprecated("Remove in v4.1.  Use GetContentSubType().")]]
	zeek::StringVal* ContentSubType() const { return content_subtype_str.get(); }
	const zeek::StringValPtr& GetContentType() const { return content_type_str; }
	const zeek::StringValPtr& GetContentSubType() const { return content_subtype_str; }
	int ContentTransferEncoding() const { return content_encoding; }

protected:
	void init();

	// {begin, continuation, end} of a header.
	void NewHeader(int len, const char* data);
	void ContHeader(int len, const char* data);
	void FinishHeader();

	void ParseMIMEHeader(MIME_Header* h);
	int LookupMIMEHeaderName(zeek::data_chunk_t name);
	bool ParseContentTypeField(MIME_Header* h);
	bool ParseContentEncodingField(MIME_Header* h);
	bool ParseFieldParameters(int len, const char* data);

	void ParseContentType(zeek::data_chunk_t type, zeek::data_chunk_t sub_type);
	void ParseContentEncoding(zeek::data_chunk_t encoding_mechanism);

	void BeginBody();
	void NewDataLine(int len, const char* data, bool trailing_CRLF);

	int CheckBoundaryDelimiter(int len, const char* data);
	void DecodeDataLine(int len, const char* data, bool trailing_CRLF);
	void DecodeBinary(int len, const char* data, bool trailing_CRLF);
	void DecodeQuotedPrintable(int len, const char* data);
	void DecodeBase64(int len, const char* data);
	void StartDecodeBase64();
	void FinishDecodeBase64();

	bool GetDataBuffer();
	void DataOctet(char ch);
	void DataOctets(int len, const char* data);
	void FlushData();
	virtual void SubmitData(int len, const char* buf);

	virtual void SubmitHeader(MIME_Header* h);
	// Submit all headers in member "headers".
	virtual void SubmitAllHeaders();

	virtual MIME_Entity* NewChildEntity() { return new MIME_Entity(message, this); }
	void BeginChildEntity();
	void EndChildEntity();

	void IllegalFormat(const char* explanation);
	void IllegalEncoding(const char* explanation);

	void DebugPrintHeaders();

	int in_header;
	int end_of_data;
	MIME_Multiline* current_header_line;
	int current_field_type;
	int need_to_parse_parameters;

	zeek::StringValPtr content_type_str;
	zeek::StringValPtr content_subtype_str;
	zeek::String* content_encoding_str;
	zeek::String* multipart_boundary;

	int content_type, content_subtype, content_encoding;

	MIME_HeaderList headers;
	MIME_Entity* parent;
	MIME_Entity* current_child_entity;

	Base64Converter* base64_decoder;

	int data_buf_length;
	char* data_buf_data;
	int data_buf_offset;

	MIME_Message* message;
	bool delay_adding_implicit_CRLF;
	bool want_all_headers;
};

// The reason I separate MIME_Message as an abstract class is to
// present the *interface* separated from its implementation to
// generate Bro events.

class MIME_Message {
public:
	explicit MIME_Message(zeek::analyzer::Analyzer* arg_analyzer)
		{
		// Cannot initialize top_level entity because we do
		// not know its type yet (MIME_Entity / MIME_Mail /
		// etc.).
		top_level = nullptr;
		finished = false;
		analyzer = arg_analyzer;
		}

	virtual ~MIME_Message()
		{
		if ( ! finished )
			reporter->AnalyzerError(analyzer,
			  "missing MIME_Message::Done() call");
		}

	virtual void Done()	{ finished = true; }

	bool Finished() const	{ return finished; }

	virtual void Deliver(int len, const char* data, bool trailing_CRLF)
		{
		top_level->Deliver(len, data, trailing_CRLF);
		}

	zeek::analyzer::Analyzer* GetAnalyzer() const	{ return analyzer; }

	// Events generated by MIME_Entity
	virtual void BeginEntity(MIME_Entity*) = 0;
	virtual void EndEntity(MIME_Entity*) = 0;
	virtual void SubmitHeader(MIME_Header* h) = 0;
	virtual void SubmitAllHeaders(MIME_HeaderList& hlist) = 0;
	virtual void SubmitData(int len, const char* buf) = 0;
	virtual bool RequestBuffer(int* plen, char** pbuf) = 0;
	virtual void SubmitEvent(int event_type, const char* detail) = 0;

protected:
	zeek::analyzer::Analyzer* analyzer;

	MIME_Entity* top_level;
	bool finished;

	[[deprecated("Remove in v4.1.  Use ToHeaderVal().")]]
	zeek::RecordVal* BuildHeaderVal(MIME_Header* h);
	[[deprecated("Remove in v4.1.  Use ToHeaderTable().")]]
	zeek::TableVal* BuildHeaderTable(MIME_HeaderList& hlist);

	zeek::RecordValPtr ToHeaderVal(MIME_Header* h);
	zeek::TableValPtr ToHeaderTable(MIME_HeaderList& hlist);
};

class MIME_Mail final : public MIME_Message {
public:
	MIME_Mail(zeek::analyzer::Analyzer* mail_conn, bool is_orig, int buf_size = 0);
	~MIME_Mail() override;
	void Done() override;

	void BeginEntity(MIME_Entity* entity) override;
	void EndEntity(MIME_Entity* entity) override;
	void SubmitHeader(MIME_Header* h) override;
	void SubmitAllHeaders(MIME_HeaderList& hlist) override;
	void SubmitData(int len, const char* buf) override;
	bool RequestBuffer(int* plen, char** pbuf) override;
	void SubmitAllData();
	void SubmitEvent(int event_type, const char* detail) override;
	void Undelivered(int len);

protected:
	int min_overlap_length;
	int max_chunk_length;
	bool is_orig;
	int buffer_start;
	int data_start;
	int compute_content_hash;
	int content_hash_length;
	EVP_MD_CTX* md5_hash;
	std::vector<const zeek::String*> entity_content;
	std::vector<const zeek::String*> all_content;

	zeek::String* data_buffer;

	uint64_t cur_entity_len;
	std::string cur_entity_id;
};

extern bool is_null_data_chunk(zeek::data_chunk_t b);
[[deprecated("Remove in v4.1.  Use analyzer::mime::to_string_val().")]]
extern zeek::StringVal* new_string_val(int length, const char* data);
[[deprecated("Remove in v4.1.  Use analyzer::mime::to_string_val().")]]
extern zeek::StringVal* new_string_val(const char* data, const char* end_of_data);
[[deprecated("Remove in v4.1.  Use analyzer::mime::to_string_val().")]]
extern zeek::StringVal* new_string_val(const zeek::data_chunk_t buf);
extern zeek::StringValPtr to_string_val(int length, const char* data);
extern zeek::StringValPtr to_string_val(const char* data, const char* end_of_data);
extern zeek::StringValPtr to_string_val(const zeek::data_chunk_t buf);
extern int fputs(zeek::data_chunk_t b, FILE* fp);
extern bool istrequal(zeek::data_chunk_t s, const char* t);
extern bool is_lws(char ch);
extern bool MIME_is_field_name_char(char ch);
extern int MIME_count_leading_lws(int len, const char* data);
extern int MIME_count_trailing_lws(int len, const char* data);
extern int MIME_skip_comments(int len, const char* data);
extern int MIME_skip_lws_comments(int len, const char* data);
extern int MIME_get_token(int len, const char* data, zeek::data_chunk_t* token,
                          bool is_boundary = false);
extern int MIME_get_slash_token_pair(int len, const char* data, zeek::data_chunk_t* first, zeek::data_chunk_t* second);
extern int MIME_get_value(int len, const char* data, zeek::String*& buf,
                          bool is_boundary = false);
extern int MIME_get_field_name(int len, const char* data, zeek::data_chunk_t* name);
extern zeek::String* MIME_decode_quoted_pairs(zeek::data_chunk_t buf);

} } // namespace analyzer::*
