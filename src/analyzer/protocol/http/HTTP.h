// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/IPAddr.h"
#include "zeek/analyzer/protocol/http/events.bif.h"
#include "zeek/analyzer/protocol/mime/MIME.h"
#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/analyzer/protocol/tcp/ContentLine.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"
#include "zeek/analyzer/protocol/zip/ZIP.h"
#include "zeek/binpac_zeek.h"

namespace zeek::analyzer::http
	{

enum CHUNKED_TRANSFER_STATE
	{
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

class HTTP_Entity final : public analyzer::mime::MIME_Entity
	{
public:
	HTTP_Entity(HTTP_Message* msg, analyzer::mime::MIME_Entity* parent_entity, int expect_body);
	~HTTP_Entity() override
		{
		if ( zip )
			{
			zip->Done();
			delete zip;
			}
		}

	void EndOfData() override;
	void Deliver(int len, const char* data, bool trailing_CRLF) override;
	bool Undelivered(int64_t len);
	int64_t BodyLength() const { return body_length; }
	int64_t HeaderLength() const { return header_length; }
	void SkipBody() { deliver_body = 0; }
	const string& FileID() const { return precomputed_file_id; }

protected:
	class UncompressedOutput;
	friend class UncompressedOutput;

	HTTP_Message* http_message;
	int chunked_transfer_state;
	int64_t content_length;
	int64_t range_length;
	int64_t expect_data_length;
	int expect_body;
	int64_t body_length;
	int64_t header_length;
	enum
		{
		IDENTITY,
		GZIP,
		COMPRESS,
		DEFLATE
		} encoding;
	analyzer::zip::ZIP_Analyzer* zip;
	bool deliver_body;
	bool is_partial_content;
	uint64_t offset;
	int64_t instance_length; // total length indicated by content-range
	bool send_size; // whether to send size indication to FAF
	std::string precomputed_file_id;

	analyzer::mime::MIME_Entity* NewChildEntity() override
		{
		return new HTTP_Entity(http_message, this, 1);
		}

	void DeliverBody(int len, const char* data, bool trailing_CRLF);
	void DeliverBodyClear(int len, const char* data, bool trailing_CRLF);

	void SubmitData(int len, const char* buf) override;

	void SetPlainDelivery(int64_t length);

	void SubmitHeader(analyzer::mime::MIME_Header* h) override;
	void SubmitAllHeaders() override;
	};

enum
	{
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

class HTTP_Message final : public analyzer::mime::MIME_Message
	{
	friend class HTTP_Entity;

public:
	HTTP_Message(HTTP_Analyzer* analyzer, analyzer::tcp::ContentLine_Analyzer* cl, bool is_orig,
	             int expect_body, int64_t init_header_length);
	~HTTP_Message() override;
	void Done(bool interrupted, const char* msg);
	void Done() override { Done(false, "message ends normally"); }

	bool Undelivered(int64_t len);

	void BeginEntity(analyzer::mime::MIME_Entity* /* entity */) override;
	void EndEntity(analyzer::mime::MIME_Entity* entity) override;
	void SubmitHeader(analyzer::mime::MIME_Header* h) override;
	void SubmitAllHeaders(analyzer::mime::MIME_HeaderList& /* hlist */) override;
	void SubmitData(int len, const char* buf) override;
	bool RequestBuffer(int* plen, char** pbuf) override;
	void SubmitAllData();
	void SubmitEvent(int event_type, const char* detail) override;

	void SubmitTrailingHeaders(analyzer::mime::MIME_HeaderList& /* hlist */);
	void SetPlainDelivery(int64_t length);
	void SetDeliverySize(int64_t length);
	void SkipEntityData();

	HTTP_Analyzer* MyHTTP_Analyzer() const { return (HTTP_Analyzer*)analyzer; }

	void Weird(const char* msg);
	bool IsOrig() { return is_orig; }

protected:
	HTTP_Analyzer* analyzer;
	analyzer::tcp::ContentLine_Analyzer* content_line;
	bool is_orig;

	char* entity_data_buffer;

	double start_time;

	int64_t body_length; // total length of entity bodies
	int64_t header_length; // total length of headers, including the request/reply line

	// Total length of content gaps that are "successfully" skipped.
	// Note: this might NOT include all content gaps!
	int64_t content_gap_length;

	HTTP_Entity* current_entity;

	RecordValPtr BuildMessageStat(bool interrupted, const char* msg);
	};

class HTTP_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer
	{
public:
	HTTP_Analyzer(Connection* conn);

	void HTTP_Header(bool is_orig, analyzer::mime::MIME_Header* h);
	void HTTP_EntityData(bool is_orig, String* entity_data);
	void HTTP_MessageDone(bool is_orig, HTTP_Message* message);
	void HTTP_Event(const char* category, const char* detail);
	void HTTP_Event(const char* category, StringValPtr detail);

	void SkipEntityData(bool is_orig);

	bool IsConnectionClose() { return connection_close; }
	int HTTP_ReplyCode() const { return reply_code; };

	// Overridden from Analyzer.
	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;

	// Overridden from analyzer::tcp::TCP_ApplicationAnalyzer
	void EndpointEOF(bool is_orig) override;
	void ConnectionFinished(bool half_finished) override;
	void ConnectionReset() override;
	void PacketWithRST() override;

	struct HTTP_VersionNumber
		{
		uint8_t major = 0;
		uint8_t minor = 0;

		bool operator==(const HTTP_VersionNumber& other) const
			{
			return minor == other.minor && major == other.major;
			}

		bool operator!=(const HTTP_VersionNumber& other) const { return ! operator==(other); }

		double ToDouble() const { return major + minor * 0.1; }
		};

	double GetRequestVersion() { return request_version.ToDouble(); };
	double GetReplyVersion() { return reply_version.ToDouble(); };
	HTTP_VersionNumber GetRequestVersionNumber() { return request_version; };
	HTTP_VersionNumber GetReplyVersionNumber() { return reply_version; };
	int GetRequestOngoing() { return request_ongoing; };
	int GetReplyOngoing() { return reply_ongoing; };

	static analyzer::Analyzer* Instantiate(Connection* conn) { return new HTTP_Analyzer(conn); }

	static bool Available()
		{
		return (http_request || http_reply || http_header || http_all_headers ||
		        http_begin_entity || http_end_entity || http_content_type || http_entity_data ||
		        http_message_done || http_event || http_stats);
		}

protected:
	void GenStats();

	int HTTP_RequestLine(const char* line, const char* end_of_line);
	int HTTP_ReplyLine(const char* line, const char* end_of_line);

	void InitHTTPMessage(analyzer::tcp::ContentLine_Analyzer* cl, HTTP_Message*& message,
	                     bool is_orig, int expect_body, int64_t init_header_length);

	const char* PrefixMatch(const char* line, const char* end_of_line, const char* prefix);
	const char* PrefixWordMatch(const char* line, const char* end_of_line, const char* prefix);

	bool ParseRequest(const char* line, const char* end_of_line);
	HTTP_VersionNumber HTTP_Version(int len, const char* data);

	void SetVersion(HTTP_VersionNumber* version, HTTP_VersionNumber new_version);

	bool RequestExpected() const { return num_requests == 0 || keep_alive; }

	void HTTP_Request();
	void HTTP_Reply();

	void RequestMade(bool interrupted, const char* msg);
	void ReplyMade(bool interrupted, const char* msg);
	void RequestClash(Val* clash_val);

	const String* UnansweredRequestMethod();

	int HTTP_ReplyCode(const char* code_str);
	int ExpectReplyMessageBody();

	StringValPtr TruncateURI(const StringValPtr& uri);

	int request_state, reply_state;
	int num_requests, num_replies;
	int num_request_lines, num_reply_lines;
	HTTP_VersionNumber request_version, reply_version;
	int keep_alive;
	int connection_close;
	int request_ongoing, reply_ongoing;

	bool connect_request;
	analyzer::pia::PIA_TCP* pia;
	// set to true after a connection was upgraded
	bool upgraded;
	// set to true when encountering an "connection" header in a reply.
	bool upgrade_connection;
	// set to the protocol string when encountering an "upgrade" header
	// in a reply.
	std::string upgrade_protocol;

	StringValPtr request_method;

	// request_URI is in the original form (may contain '%<hex><hex>'
	// sequences).
	StringValPtr request_URI;

	// unescaped_URI does not contain escaped sequences.
	StringValPtr unescaped_URI;

	std::queue<StringValPtr> unanswered_requests;

	int reply_code;
	StringValPtr reply_reason_phrase;

	analyzer::tcp::ContentLine_Analyzer* content_line_orig;
	analyzer::tcp::ContentLine_Analyzer* content_line_resp;

	HTTP_Message* request_message;
	HTTP_Message* reply_message;
	};

extern bool is_reserved_URI_char(unsigned char ch);
extern bool is_unreserved_URI_char(unsigned char ch);
extern void escape_URI_char(unsigned char ch, unsigned char*& p);
extern String* unescape_URI(const u_char* line, const u_char* line_end,
                            analyzer::Analyzer* analyzer);

	} // namespace zeek::analyzer::http
