// $Id: HTTP.h 6942 2009-11-16 03:54:08Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef http_h
#define http_h

#include "TCP.h"
#include "ContentLine.h"
#include "MIME.h"
#include "binpac_bro.h"
#include "ZIP.h"

enum CHUNKED_TRANSFER_STATE {
	NON_CHUNKED_TRANSFER,
	BEFORE_CHUNK,
	EXPECT_CHUNK_SIZE,
	EXPECT_CHUNK_DATA,
	EXPECT_CHUNK_DATA_CRLF,
	EXPECT_CHUNK_TRAILER,
	EXPECT_NOTHING,
};

class HTTP_Entity;
class HTTP_Message;
class HTTP_Analyzer;

class HTTP_Entity : public MIME_Entity {
public:
	HTTP_Entity(HTTP_Message* msg, MIME_Entity* parent_entity,
			int expect_body);
	~HTTP_Entity()
		{
#ifdef HAVE_LIBZ
		if ( zip )
			{ zip->Done(); delete zip; }
#endif
		}

	void EndOfData();
	void Deliver(int len, const char* data, int trailing_CRLF);
	int Undelivered(int len);
	int BodyLength() const 		{ return body_length; }
	int HeaderLength() const 	{ return header_length; }
	void SkipBody() 		{ deliver_body = 0; }

protected:
	class UncompressedOutput;
	friend class UncompressedOutput;

	HTTP_Message* http_message;
	int chunked_transfer_state;
	int content_length;
	int expect_data_length;
	int expect_body;
	int body_length;
	int header_length;
	int deliver_body;
	enum { IDENTITY, GZIP, COMPRESS, DEFLATE } encoding;
#ifdef HAVE_LIBZ
	ZIP_Analyzer* zip;
#endif

	MIME_Entity* NewChildEntity() { return new HTTP_Entity(http_message, this, 1); }

	void DeliverBody(int len, const char* data, int trailing_CRLF);
	void DeliverBodyClear(int len, const char* data, int trailing_CRLF);

	void SubmitData(int len, const char* buf);

	void SetPlainDelivery(int length);

	void SubmitHeader(MIME_Header* h);
	void SubmitAllHeaders();
};

enum {
	HTTP_BODY_NOT_EXPECTED,
	HTTP_BODY_EXPECTED,
	HTTP_BODY_MAYBE,
};

// Finishing HTTP Messages:
//
// HTTP_Entity::SubmitAllHeaders	-> EndOfData (no body)
// HTTP_Entity::Deliver	-> EndOfData (end of body)
// HTTP_Analyzer::Done	-> {Request,Reply}Made (connection terminated)
// {Request,Reply}Made	-> HTTP_Message::Done
// HTTP_Message::Done	-> MIME_Message::Done, EndOfData, HTTP_MessageDone
// MIME_Entity::EndOfData	-> Message::EndEntity
// HTTP_Message::EndEntity	-> Message::Done
// HTTP_MessageDone	-> {Request,Reply}Made

class HTTP_Message : public MIME_Message {
public:
	HTTP_Message(HTTP_Analyzer* analyzer, ContentLine_Analyzer* cl,
			 bool is_orig, int expect_body, int init_header_length);
	~HTTP_Message();
	void Done(const int interrupted, const char* msg);
	void Done() { Done(0, "message ends normally"); }

	int Undelivered(int len);

	void BeginEntity(MIME_Entity* /* entity */);
	void EndEntity(MIME_Entity* entity);
	void SubmitHeader(MIME_Header* h);
	void SubmitAllHeaders(MIME_HeaderList& /* hlist */);
	void SubmitData(int len, const char* buf);
	int RequestBuffer(int* plen, char** pbuf);
	void SubmitAllData();
	void SubmitEvent(int event_type, const char* detail);

	void SubmitTrailingHeaders(MIME_HeaderList& /* hlist */);
	void SetPlainDelivery(int length);
	void SkipEntityData();

	HTTP_Analyzer* MyHTTP_Analyzer() const
		{ return (HTTP_Analyzer*) analyzer; }

	void Weird(const char* msg);
	bool IsOrig()	{ return is_orig; }

protected:
	HTTP_Analyzer* analyzer;
	ContentLine_Analyzer* content_line;
	bool is_orig;

	vector<const BroString*> buffers;

	// Controls the total buffer size within http_entity_data_delivery_size.
	int total_buffer_size;

	int buffer_offset, buffer_size;
	BroString* data_buffer;

	double start_time;

	int body_length;	// total length of entity bodies
	int header_length;	// total length of headers, including the request/reply line

	// Total length of content gaps that are "successfully" skipped.
	// Note: this might NOT include all content gaps!
	int content_gap_length;

	HTTP_Entity* current_entity;

	int InitBuffer(int length);
	void DeliverEntityData();

	Val* BuildMessageStat(const int interrupted, const char* msg);
};

class HTTP_Analyzer : public TCP_ApplicationAnalyzer {
public:
	HTTP_Analyzer(Connection* conn);
	~HTTP_Analyzer();

	void Undelivered(TCP_Endpoint* sender, int seq, int len);

	void HTTP_Header(int is_orig, MIME_Header* h);
	void HTTP_EntityData(int is_orig, const BroString* entity_data);
	void HTTP_MessageDone(int is_orig, HTTP_Message* message);
	void HTTP_Event(const char* category, const char* detail);
	void HTTP_Event(const char* category, StringVal *detail);

	void SkipEntityData(int is_orig);

	// Overriden from Analyzer.
	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(int seq, int len, bool orig);
	virtual int RewritingTrace()
		{ return rewriting_http_trace || TCP_ApplicationAnalyzer::RewritingTrace(); }

	// Overriden from TCP_ApplicationAnalyzer
	virtual void EndpointEOF(bool is_orig);
	virtual void ConnectionFinished(int half_finished);
	virtual void ConnectionReset();
	virtual void PacketWithRST();

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new HTTP_Analyzer(conn); }

	static bool Available()
		{ return (http_request || http_reply) && !FLAGS_use_binpac; }

	int IsConnectionClose()		{ return connection_close; }

protected:
	void GenStats();

	int HTTP_RequestLine(const char* line, const char* end_of_line);
	int HTTP_ReplyLine(const char* line, const char* end_of_line);

	void InitHTTPMessage(ContentLine_Analyzer* cl, HTTP_Message*& message, bool is_orig,
				int expect_body, int init_header_length);

	const char* PrefixMatch(const char* line, const char* end_of_line,
				const char* prefix);
	const char* PrefixWordMatch(const char* line, const char* end_of_line,
				const char* prefix);

	int ParseRequest(const char* line, const char* end_of_line);
	double HTTP_Version(int len, const char* data);

	void SetVersion(double& version, double new_version);

	int RequestExpected() const { return num_requests == 0 || keep_alive; }

	void HTTP_Request();
	void HTTP_Reply();

	void RequestMade(const int interrupted, const char* msg);
	void ReplyMade(const int interrupted, const char* msg);
	void RequestClash(Val* clash_val);

	const BroString* UnansweredRequestMethod();

	void ParseVersion(data_chunk_t ver, const uint32* host, bool user_agent);
	int HTTP_ReplyCode(const char* code_str);
	int ExpectReplyMessageBody();

	StringVal* TruncateURI(StringVal* uri);

	int request_state, reply_state;
	int num_requests, num_replies;
	int num_request_lines, num_reply_lines;
	double request_version, reply_version;
	int keep_alive;
	int connection_close;
	int request_ongoing, reply_ongoing;

	Val* request_method;

	// request_URI is in the original form (may contain '%<hex><hex>'
	// sequences).
	Val* request_URI;

	// unescaped_URI does not contain escaped sequences.
	Val* unescaped_URI;

	std::queue<Val*> unanswered_requests;

	int reply_code;
	Val* reply_reason_phrase;

	ContentLine_Analyzer* content_line_orig;
	ContentLine_Analyzer* content_line_resp;

	HTTP_Message* request_message;
	HTTP_Message* reply_message;
};

extern int is_reserved_URI_char(unsigned char ch);
extern int is_unreserved_URI_char(unsigned char ch);
extern void escape_URI_char(unsigned char ch, unsigned char*& p);
extern BroString* unescape_URI(const u_char* line, const u_char* line_end,
				Analyzer* analyzer);

#endif
