#ifndef ANALYZER_PROTOCOL_MIME_MIME_H
#define ANALYZER_PROTOCOL_MIME_MIME_H

#include <assert.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <vector>
#include <queue>
using namespace std;

#include "Base64.h"
#include "BroString.h"
#include "analyzer/Analyzer.h"

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
	BroString* get_concatenated_line();

protected:
	vector<const BroString*> buffer;
	BroString* line;
};

class MIME_Header {
public:
	MIME_Header(MIME_Multiline* hl);
	~MIME_Header();

	data_chunk_t get_name() const	{ return name; }
	data_chunk_t get_value() const	{ return value; }

	data_chunk_t get_value_token();
	data_chunk_t get_value_after_token();

protected:
	int get_first_token();

	MIME_Multiline* lines;
	data_chunk_t name;
	data_chunk_t value;
	data_chunk_t value_token, rest_value;
};


// declare(PList, MIME_Header);
typedef vector<MIME_Header*> MIME_HeaderList;

class MIME_Entity {
public:
	MIME_Entity(MIME_Message* output_message, MIME_Entity* parent_entity);
	virtual ~MIME_Entity();

	virtual void Deliver(int len, const char* data, int trailing_CRLF);
	virtual void EndOfData();

	MIME_Entity* Parent() const { return parent; }
	int MIMEContentType() const { return content_type; }
	StringVal* ContentType() const { return content_type_str; }
	StringVal* ContentSubType() const { return content_subtype_str; }
	int ContentTransferEncoding() const { return content_encoding; }

protected:
	void init();

	// {begin, continuation, end} of a header.
	void NewHeader(int len, const char* data);
	void ContHeader(int len, const char* data);
	void FinishHeader();

	void ParseMIMEHeader(MIME_Header* h);
	int LookupMIMEHeaderName(data_chunk_t name);
	int ParseContentTypeField(MIME_Header* h);
	int ParseContentEncodingField(MIME_Header* h);
	int ParseFieldParameters(int len, const char* data);

	void ParseContentType(data_chunk_t type, data_chunk_t sub_type);
	void ParseContentEncoding(data_chunk_t encoding_mechanism);
	void ParseParameter(data_chunk_t attr, data_chunk_t val);

	void BeginBody();
	void NewDataLine(int len, const char* data, int trailing_CRLF);

	int CheckBoundaryDelimiter(int len, const char* data);
	void DecodeDataLine(int len, const char* data, int trailing_CRLF);
	void DecodeBinary(int len, const char* data, int trailing_CRLF);
	void DecodeQuotedPrintable(int len, const char* data);
	void DecodeBase64(int len, const char* data);
	void StartDecodeBase64();
	void FinishDecodeBase64();

	int GetDataBuffer();
	void DataOctet(char ch);
	void DataOctets(int len, const char* data);
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

	StringVal* content_type_str;
	StringVal* content_subtype_str;
	BroString* content_encoding_str;
	BroString* multipart_boundary;

	int content_type, content_subtype, content_encoding;

	MIME_HeaderList headers;
	MIME_Entity* parent;
	MIME_Entity* current_child_entity;

	Base64Converter* base64_decoder;

	int data_buf_length;
	char* data_buf_data;
	int data_buf_offset;

	MIME_Message* message;
};

// The reason I separate MIME_Message as an abstract class is to
// present the *interface* separated from its implementation to
// generate Bro events.

class MIME_Message {
public:
	MIME_Message(analyzer::Analyzer* arg_analyzer)
		{
		// Cannot initialize top_level entity because we do
		// not know its type yet (MIME_Entity / MIME_Mail /
		// etc.).
		top_level = 0;
		finished = 0;
		analyzer = arg_analyzer;
		}

	virtual ~MIME_Message()
		{
		if ( ! finished )
			reporter->AnalyzerError(analyzer,
			  "missing MIME_Message::Done() call");
		}

	virtual void Done()	{ finished = 1; }

	int Finished() const	{ return finished; }

	virtual void Deliver(int len, const char* data, int trailing_CRLF)
		{
		top_level->Deliver(len, data, trailing_CRLF);
		}

	analyzer::Analyzer* GetAnalyzer() const	{ return analyzer; }

	// Events generated by MIME_Entity
	virtual void BeginEntity(MIME_Entity*) = 0;
	virtual void EndEntity(MIME_Entity*) = 0;
	virtual void SubmitHeader(MIME_Header* h) = 0;
	virtual void SubmitAllHeaders(MIME_HeaderList& hlist) = 0;
	virtual void SubmitData(int len, const char* buf) = 0;
	virtual int RequestBuffer(int* plen, char** pbuf) = 0;
	virtual void SubmitEvent(int event_type, const char* detail) = 0;

protected:
	analyzer::Analyzer* analyzer;

	MIME_Entity* top_level;
	int finished;

	RecordVal* BuildHeaderVal(MIME_Header* h);
	TableVal* BuildHeaderTable(MIME_HeaderList& hlist);
};

class MIME_Mail : public MIME_Message {
public:
	MIME_Mail(analyzer::Analyzer* mail_conn, int buf_size = 0);
	~MIME_Mail();
	void Done();

	void BeginEntity(MIME_Entity* entity);
	void EndEntity(MIME_Entity* entity);
	void SubmitHeader(MIME_Header* h);
	void SubmitAllHeaders(MIME_HeaderList& hlist);
	void SubmitData(int len, const char* buf);
	int RequestBuffer(int* plen, char** pbuf);
	void SubmitAllData();
	void SubmitEvent(int event_type, const char* detail);
	void Undelivered(int len);

protected:
	int min_overlap_length;
	int max_chunk_length;
	int buffer_start;
	int data_start;
	int compute_content_hash;
	int content_hash_length;
	MD5_CTX md5_hash;
	vector<const BroString*> entity_content;
	vector<const BroString*> all_content;

	BroString* data_buffer;

	uint64 cur_entity_len;
};


extern int is_null_data_chunk(data_chunk_t b);
extern StringVal* new_string_val(int length, const char* data);
extern StringVal* new_string_val(const char* data, const char* end_of_data);
extern StringVal* new_string_val(const data_chunk_t buf);
extern int fputs(data_chunk_t b, FILE* fp);
extern int strcasecmp_n(data_chunk_t s, const char* t);
extern int is_lws(char ch);
extern int MIME_is_field_name_char(char ch);
extern int MIME_count_leading_lws(int len, const char* data);
extern int MIME_count_trailing_lws(int len, const char* data);
extern int MIME_skip_comments(int len, const char* data);
extern int MIME_skip_lws_comments(int len, const char* data);
extern int MIME_get_token(int len, const char* data, data_chunk_t* token);
extern int MIME_get_slash_token_pair(int len, const char* data, data_chunk_t* first, data_chunk_t* second);
extern int MIME_get_value(int len, const char* data, BroString*& buf);
extern int MIME_get_field_name(int len, const char* data, data_chunk_t* name);
extern BroString* MIME_decode_quoted_pairs(data_chunk_t buf);

} } // namespace analyzer::* 

#endif
