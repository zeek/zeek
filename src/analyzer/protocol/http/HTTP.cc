// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/http/HTTP.h"

#include "zeek/zeek-config.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <string>

#include "zeek/Event.h"
#include "zeek/NetVar.h"
#include "zeek/analyzer/protocol/http/events.bif.h"
#include "zeek/analyzer/protocol/mime/MIME.h"
#include "zeek/file_analysis/Manager.h"

namespace zeek::analyzer::http
	{

const bool DEBUG_http = false;

// The EXPECT_*_NOTHING states are used to prevent further parsing. Used if a
// message was interrupted.
enum HTTP_ExpectRequest
	{
	EXPECT_REQUEST_LINE,
	EXPECT_REQUEST_MESSAGE,
	EXPECT_REQUEST_TRAILER,
	EXPECT_REQUEST_NOTHING,
	};

enum HTTP_ExpectReply
	{
	EXPECT_REPLY_LINE,
	EXPECT_REPLY_MESSAGE,
	EXPECT_REPLY_TRAILER,
	EXPECT_REPLY_NOTHING,
	};

HTTP_Entity::HTTP_Entity(HTTP_Message* arg_message, analyzer::mime::MIME_Entity* parent_entity,
                         int arg_expect_body)
	: analyzer::mime::MIME_Entity(arg_message, parent_entity)
	{
	http_message = arg_message;
	expect_body = arg_expect_body;
	chunked_transfer_state = NON_CHUNKED_TRANSFER;
	content_length = range_length = -1; // unspecified
	expect_data_length = 0;
	body_length = 0;
	header_length = 0;
	deliver_body = true;
	encoding = IDENTITY;
	zip = nullptr;
	is_partial_content = false;
	offset = 0;
	instance_length = -1; // unspecified
	send_size = true;
	// Always override what MIME_Entity set for want_all_headers: HTTP doesn't
	// raise the generic MIME events, but rather it's own specific ones.
	want_all_headers = (bool)http_all_headers;
	}

void HTTP_Entity::EndOfData()
	{
	if ( DEBUG_http )
		DEBUG_MSG("%.6f: end of data\n", run_state::network_time);

	if ( zip )
		{
		zip->Done();
		delete zip;
		zip = nullptr;
		encoding = IDENTITY;
		}

	if ( body_length )
		http_message->MyHTTP_Analyzer()->ForwardEndOfData(http_message->IsOrig());

	analyzer::mime::MIME_Entity::EndOfData();
	}

void HTTP_Entity::Deliver(int len, const char* data, bool trailing_CRLF)
	{
	if ( DEBUG_http )
		{
		DEBUG_MSG("%.6f HTTP_Entity::Deliver len=%d, in_header=%d\n", run_state::network_time, len,
		          in_header);
		}

	if ( end_of_data )
		{
		// Multipart entities may have trailers
		if ( content_type != analyzer::mime::CONTENT_TYPE_MULTIPART )
			IllegalFormat("data trailing the end of entity");
		return;
		}

	if ( in_header )
		{
		if ( ! trailing_CRLF )
			http_message->MyHTTP_Analyzer()->Weird("http_no_crlf_in_header_list");

		header_length += len;
		analyzer::mime::MIME_Entity::Deliver(len, data, trailing_CRLF);
		return;
		}

	// Entity body.
	if ( content_type == analyzer::mime::CONTENT_TYPE_MULTIPART ||
	     content_type == analyzer::mime::CONTENT_TYPE_MESSAGE )
		DeliverBody(len, data, trailing_CRLF);

	else if ( chunked_transfer_state != NON_CHUNKED_TRANSFER )
		{
		switch ( chunked_transfer_state )
			{
			case EXPECT_CHUNK_SIZE:
				ASSERT(trailing_CRLF);
				if ( ! util::atoi_n(len, data, nullptr, 16, expect_data_length) )
					{
					http_message->Weird("HTTP_bad_chunk_size");
					expect_data_length = 0;
					}

				if ( expect_data_length > 0 )
					{
					chunked_transfer_state = EXPECT_CHUNK_DATA;
					SetPlainDelivery(expect_data_length);
					}
				else
					{
					// This is the last chunk
					in_header = 1;
					chunked_transfer_state = EXPECT_CHUNK_TRAILER;
					}
				break;

			case EXPECT_CHUNK_DATA:
				ASSERT(! trailing_CRLF);
				ASSERT(len <= expect_data_length);
				expect_data_length -= len;
				if ( expect_data_length <= 0 )
					{
					SetPlainDelivery(0);
					chunked_transfer_state = EXPECT_CHUNK_DATA_CRLF;
					}
				DeliverBody(len, data, false);
				break;

			case EXPECT_CHUNK_DATA_CRLF:
				ASSERT(trailing_CRLF);
				if ( len > 0 )
					IllegalFormat("inaccurate chunk size: data before <CR><LF>");
				chunked_transfer_state = EXPECT_CHUNK_SIZE;
				break;
			}
		}

	else if ( content_length >= 0 )
		{
		ASSERT(! trailing_CRLF);
		ASSERT(len <= expect_data_length);

		DeliverBody(len, data, false);

		expect_data_length -= len;
		if ( expect_data_length <= 0 )
			{
			SetPlainDelivery(0);
			http_message->SetDeliverySize(-1);
			EndOfData();
			}
		}

	else
		DeliverBody(len, data, trailing_CRLF);
	}

class HTTP_Entity::UncompressedOutput : public analyzer::OutputHandler
	{
public:
	UncompressedOutput(HTTP_Entity* e) { entity = e; }
	void DeliverStream(int len, const u_char* data, bool orig) override
		{
		entity->DeliverBodyClear(len, (char*)data, false);
		}

private:
	HTTP_Entity* entity;
	};

void HTTP_Entity::DeliverBody(int len, const char* data, bool trailing_CRLF)
	{
	if ( encoding == GZIP || encoding == DEFLATE )
		{
		analyzer::zip::ZIP_Analyzer::Method method = encoding == GZIP
		                                                 ? analyzer::zip::ZIP_Analyzer::GZIP
		                                                 : analyzer::zip::ZIP_Analyzer::DEFLATE;

		if ( ! zip )
			{
			// We don't care about the direction here.
			zip = new analyzer::zip::ZIP_Analyzer(http_message->MyHTTP_Analyzer()->Conn(), false,
			                                      method);
			zip->SetOutputHandler(new UncompressedOutput(this));
			}

		zip->NextStream(len, (const u_char*)data, false);
		}
	else
		DeliverBodyClear(len, data, trailing_CRLF);
	}

void HTTP_Entity::DeliverBodyClear(int len, const char* data, bool trailing_CRLF)
	{
	bool new_data = (body_length == 0);

	body_length += len;
	if ( trailing_CRLF )
		body_length += 2;

	if ( deliver_body )
		analyzer::mime::MIME_Entity::Deliver(len, data, trailing_CRLF);

	zeek::detail::Rule::PatternType rule = http_message->IsOrig()
	                                           ? zeek::detail::Rule::HTTP_REQUEST_BODY
	                                           : zeek::detail::Rule::HTTP_REPLY_BODY;

	http_message->MyHTTP_Analyzer()->Conn()->Match(
		rule, (const u_char*)data, len, http_message->IsOrig(), new_data, false, new_data);

	// FIXME: buffer data for forwarding (matcher might match later).
	http_message->MyHTTP_Analyzer()->ForwardStream(len, (const u_char*)data,
	                                               http_message->IsOrig());
	}

// Returns 1 if the undelivered bytes are completely within the body,
// otherwise returns 0.
bool HTTP_Entity::Undelivered(int64_t len)
	{
	if ( DEBUG_http )
		{
		DEBUG_MSG("Content gap %" PRId64 ", expect_data_length %" PRId64 "\n", len,
		          expect_data_length);
		}

	// Don't propagate an entity (file) gap if we're still in the headers,
	// or the body length was declared to be zero.
	if ( (end_of_data && in_header) || body_length == 0 )
		return false;

	if ( is_partial_content )
		{
		precomputed_file_id = file_mgr->Gap(
			body_length, len, http_message->MyHTTP_Analyzer()->GetAnalyzerTag(),
			http_message->MyHTTP_Analyzer()->Conn(), http_message->IsOrig(), precomputed_file_id);

		offset += len;
		}
	else
		precomputed_file_id = file_mgr->Gap(
			body_length, len, http_message->MyHTTP_Analyzer()->GetAnalyzerTag(),
			http_message->MyHTTP_Analyzer()->Conn(), http_message->IsOrig(), precomputed_file_id);

	if ( chunked_transfer_state != NON_CHUNKED_TRANSFER )
		{
		if ( chunked_transfer_state == EXPECT_CHUNK_DATA && expect_data_length >= len )
			{
			body_length += len;
			expect_data_length -= len;

			SetPlainDelivery(expect_data_length);
			if ( expect_data_length == 0 )
				chunked_transfer_state = EXPECT_CHUNK_DATA_CRLF;

			return true;
			}
		else
			return false;
		}

	else if ( content_length >= 0 )
		{
		if ( expect_data_length >= len )
			{
			body_length += len;
			expect_data_length -= len;

			SetPlainDelivery(expect_data_length);

			if ( expect_data_length <= 0 )
				EndOfData();

			return true;
			}

		else
			return false;
		}

	return false;
	}

void HTTP_Entity::SubmitData(int len, const char* buf)
	{
	if ( deliver_body )
		analyzer::mime::MIME_Entity::SubmitData(len, buf);

	if ( send_size && (encoding == GZIP || encoding == DEFLATE) )
		// Auto-decompress in DeliverBody invalidates sizes derived from headers
		send_size = false;

	if ( is_partial_content )
		{
		if ( send_size && instance_length > 0 )
			precomputed_file_id = file_mgr->SetSize(
				instance_length, http_message->MyHTTP_Analyzer()->GetAnalyzerTag(),
				http_message->MyHTTP_Analyzer()->Conn(), http_message->IsOrig(),
				precomputed_file_id);

		precomputed_file_id = file_mgr->DataIn(reinterpret_cast<const u_char*>(buf), len, offset,
		                                       http_message->MyHTTP_Analyzer()->GetAnalyzerTag(),
		                                       http_message->MyHTTP_Analyzer()->Conn(),
		                                       http_message->IsOrig(), precomputed_file_id);

		offset += len;
		}
	else
		{
		if ( send_size && content_length > 0 )
			precomputed_file_id = file_mgr->SetSize(
				content_length, http_message->MyHTTP_Analyzer()->GetAnalyzerTag(),
				http_message->MyHTTP_Analyzer()->Conn(), http_message->IsOrig(),
				precomputed_file_id);

		precomputed_file_id = file_mgr->DataIn(reinterpret_cast<const u_char*>(buf), len,
		                                       http_message->MyHTTP_Analyzer()->GetAnalyzerTag(),
		                                       http_message->MyHTTP_Analyzer()->Conn(),
		                                       http_message->IsOrig(), precomputed_file_id);
		}

	send_size = false;
	}

void HTTP_Entity::SetPlainDelivery(int64_t length)
	{
	ASSERT(length >= 0);
	ASSERT(length == 0 || ! in_header);

	http_message->SetPlainDelivery(length);

	// If we skip HTTP data, the skipped part will appear as
	// 'undelivered' data, so we do not need to adjust
	// expect_data_length.
	}

void HTTP_Entity::SubmitHeader(analyzer::mime::MIME_Header* h)
	{
	if ( analyzer::mime::istrequal(h->get_name(), "content-length") )
		{
		data_chunk_t vt = h->get_value_token();
		if ( ! analyzer::mime::is_null_data_chunk(vt) )
			{
			int64_t n;
			if ( util::atoi_n(vt.length, vt.data, nullptr, 10, n) )
				{
				content_length = n;

				if ( is_partial_content && range_length != content_length )
					{
					// Possible evasion attempt.
					http_message->Weird("HTTP_range_not_matching_len");

					// Take the maximum of both lengths to avoid evasions.
					if ( range_length > content_length )
						content_length = range_length;
					}
				}
			else
				content_length = 0;
			}
		}

	// Figure out content-length for HTTP 206 Partial Content response
	else if ( analyzer::mime::istrequal(h->get_name(), "content-range") &&
	          http_message->MyHTTP_Analyzer()->HTTP_ReplyCode() == 206 )
		{
		data_chunk_t vt = h->get_value_token();
		string byte_unit(vt.data, vt.length);
		vt = h->get_value_after_token();
		string byte_range(vt.data, vt.length);
		byte_range.erase(remove(byte_range.begin(), byte_range.end(), ' '), byte_range.end());

		if ( byte_unit != "bytes" )
			{
			http_message->Weird("HTTP_content_range_unknown_byte_unit");
			return;
			}

		size_t p = byte_range.find('/');
		if ( p == string::npos )
			{
			http_message->Weird("HTTP_content_range_cannot_parse");
			return;
			}

		string byte_range_resp_spec = byte_range.substr(0, p);
		string instance_length_str = byte_range.substr(p + 1);

		p = byte_range_resp_spec.find('-');
		if ( p == string::npos )
			{
			http_message->Weird("HTTP_content_range_cannot_parse");
			return;
			}

		string first_byte_pos = byte_range_resp_spec.substr(0, p);
		string last_byte_pos = byte_range_resp_spec.substr(p + 1);

		if ( DEBUG_http )
			DEBUG_MSG("Parsed Content-Range: %s %s-%s/%s\n", byte_unit.c_str(),
			          first_byte_pos.c_str(), last_byte_pos.c_str(), instance_length_str.c_str());

		int64_t f, l;
		util::atoi_n(first_byte_pos.size(), first_byte_pos.c_str(), nullptr, 10, f);
		util::atoi_n(last_byte_pos.size(), last_byte_pos.c_str(), nullptr, 10, l);
		int64_t len = l - f + 1;

		if ( DEBUG_http )
			DEBUG_MSG("Content-Range length = %" PRId64 "\n", len);

		if ( len > 0 )
			{
			if ( instance_length_str != "*" )
				{
				if ( ! util::atoi_n(instance_length_str.size(), instance_length_str.c_str(),
				                    nullptr, 10, instance_length) )
					instance_length = 0;
				}

			is_partial_content = true;
			offset = f;
			range_length = len;

			if ( content_length > 0 )
				{
				if ( content_length != range_length )
					{
					// Possible evasion attempt.
					http_message->Weird("HTTP_range_not_matching_len");

					// Take the maximum of both lengths to avoid evasions.
					if ( range_length > content_length )
						content_length = range_length;
					}
				}
			else
				content_length = range_length;
			}
		else
			{
			http_message->Weird("HTTP_non_positive_content_range");
			return;
			}
		}

	else if ( analyzer::mime::istrequal(h->get_name(), "transfer-encoding") )
		{
		HTTP_Analyzer::HTTP_VersionNumber http_version;

		if ( http_message->analyzer->GetRequestOngoing() )
			http_version = http_message->analyzer->GetRequestVersionNumber();
		else // reply_ongoing
			http_version = http_message->analyzer->GetReplyVersionNumber();

		data_chunk_t vt = h->get_value_token();
		if ( analyzer::mime::istrequal(vt, "chunked") &&
		     http_version == HTTP_Analyzer::HTTP_VersionNumber{1, 1} )
			chunked_transfer_state = BEFORE_CHUNK;
		}

	else if ( analyzer::mime::istrequal(h->get_name(), "content-encoding") )
		{
		data_chunk_t vt = h->get_value_token();
		if ( analyzer::mime::istrequal(vt, "gzip") || analyzer::mime::istrequal(vt, "x-gzip") )
			encoding = GZIP;
		if ( analyzer::mime::istrequal(vt, "deflate") )
			encoding = DEFLATE;
		}

	analyzer::mime::MIME_Entity::SubmitHeader(h);
	}

void HTTP_Entity::SubmitAllHeaders()
	{
	// in_header should be set to false when SubmitAllHeaders() is called.
	ASSERT(! in_header);

	if ( DEBUG_http )
		DEBUG_MSG("%.6f end of headers\n", run_state::network_time);

	if ( Parent() && Parent()->MIMEContentType() == analyzer::mime::CONTENT_TYPE_MULTIPART )
		{
		// Don't treat single \r or \n characters in the multipart body content
		// as lines because the MIME_Entity code will implicitly add back a
		// \r\n for each line it receives.  We do this instead of setting
		// plain delivery mode for the content line analyzer because
		// the size of the content to deliver "plainly" may be unknown
		// and just leaving it in that mode indefinitely screws up the
		// detection of multipart boundaries.
		http_message->content_line->SuppressWeirds(true);
		http_message->content_line->SetCRLFAsEOL(0);
		}

	if ( content_length >= 0 )
		http_message->SetDeliverySize(content_length);

	// The presence of a message-body in a request is signaled by
	// the inclusion of a Content-Length or Transfer-Encoding
	// header field in the request's message-headers.
	if ( chunked_transfer_state == EXPECT_CHUNK_TRAILER )
		{
		http_message->SubmitTrailingHeaders(headers);
		chunked_transfer_state = EXPECT_NOTHING;
		EndOfData();
		return;
		}

	analyzer::mime::MIME_Entity::SubmitAllHeaders();

	if ( expect_body == HTTP_BODY_NOT_EXPECTED )
		{
		EndOfData();
		return;
		}

	if ( content_type == analyzer::mime::CONTENT_TYPE_MULTIPART ||
	     content_type == analyzer::mime::CONTENT_TYPE_MESSAGE )
		{
		// Do nothing.
		// Make sure that we check for multiple/message contents first,
		// because we do not have to turn on .
		if ( chunked_transfer_state != NON_CHUNKED_TRANSFER )
			{
			http_message->Weird("HTTP_chunked_transfer_for_multipart_message");
			}
		}

	else if ( chunked_transfer_state != NON_CHUNKED_TRANSFER )
		chunked_transfer_state = EXPECT_CHUNK_SIZE;

	else if ( content_length >= 0 )
		{
		if ( content_length > 0 )
			{
			expect_data_length = content_length;
			SetPlainDelivery(content_length);
			}
		else
			EndOfData(); // handle the case that content-length = 0
		}

	// Turn plain delivery on permanently for compressed bodies without
	// content-length headers or if connection is to be closed afterwards
	// anyway.
	else if ( http_message->MyHTTP_Analyzer()->IsConnectionClose() || encoding == GZIP ||
	          encoding == DEFLATE )
		{
		// FIXME: Using INT_MAX is kind of a hack here.  Better
		// would be to make -1 as special value interpreted as
		// "until the end of the connection".
		expect_data_length = INT_MAX;
		SetPlainDelivery(INT_MAX);
		}

	else
		{
		if ( expect_body != HTTP_BODY_EXPECTED )
			// there is no body
			EndOfData();
		}
	}

HTTP_Message::HTTP_Message(HTTP_Analyzer* arg_analyzer, analyzer::tcp::ContentLine_Analyzer* arg_cl,
                           bool arg_is_orig, int expect_body, int64_t init_header_length)
	: analyzer::mime::MIME_Message(arg_analyzer)
	{
	analyzer = arg_analyzer;
	content_line = arg_cl;
	is_orig = arg_is_orig;

	current_entity = nullptr;
	top_level = new HTTP_Entity(this, nullptr, expect_body);
	entity_data_buffer = nullptr;
	BeginEntity(top_level);

	start_time = run_state::network_time;
	body_length = 0;
	content_gap_length = 0;
	header_length = init_header_length;
	}

HTTP_Message::~HTTP_Message()
	{
	delete top_level;
	delete[] entity_data_buffer;
	}

RecordValPtr HTTP_Message::BuildMessageStat(bool interrupted, const char* msg)
	{
	static auto http_message_stat = id::find_type<RecordType>("http_message_stat");
	auto stat = make_intrusive<RecordVal>(http_message_stat);
	int field = 0;
	stat->AssignTime(field++, start_time);
	stat->Assign(field++, interrupted);
	stat->Assign(field++, msg);
	stat->Assign(field++, static_cast<uint64_t>(body_length));
	stat->Assign(field++, static_cast<uint64_t>(content_gap_length));
	stat->Assign(field++, static_cast<uint64_t>(header_length));
	return stat;
	}

void HTTP_Message::Done(bool interrupted, const char* detail)
	{
	if ( finished )
		return;

	analyzer::mime::MIME_Message::Done();

	// DEBUG_MSG("%.6f HTTP message done.\n", run_state::network_time);
	top_level->EndOfData();

	if ( is_orig || MyHTTP_Analyzer()->HTTP_ReplyCode() != 206 )
		{
		// multipart/byteranges may span multiple connections, so don't EOF.
		HTTP_Entity* he = dynamic_cast<HTTP_Entity*>(top_level);

		if ( he && ! he->FileID().empty() )
			file_mgr->EndOfFile(he->FileID());
		else
			file_mgr->EndOfFile(MyHTTP_Analyzer()->GetAnalyzerTag(), MyHTTP_Analyzer()->Conn(),
			                    is_orig);
		}

	if ( http_message_done )
		GetAnalyzer()->EnqueueConnEvent(http_message_done, analyzer->ConnVal(),
		                                val_mgr->Bool(is_orig),
		                                BuildMessageStat(interrupted, detail));

	MyHTTP_Analyzer()->HTTP_MessageDone(is_orig, this);
	}

bool HTTP_Message::Undelivered(int64_t len)
	{
	HTTP_Entity* e = current_entity ? current_entity : static_cast<HTTP_Entity*>(top_level);

	if ( e && e->Undelivered(len) )
		{
		content_gap_length += len;
		return true;
		}

	return false;
	}

void HTTP_Message::BeginEntity(analyzer::mime::MIME_Entity* entity)
	{
	if ( DEBUG_http )
		DEBUG_MSG("%.6f: begin entity (%d)\n", run_state::network_time, is_orig);

	current_entity = (HTTP_Entity*)entity;

	if ( http_begin_entity )
		analyzer->EnqueueConnEvent(http_begin_entity, analyzer->ConnVal(), val_mgr->Bool(is_orig));
	}

void HTTP_Message::EndEntity(analyzer::mime::MIME_Entity* entity)
	{
	if ( DEBUG_http )
		DEBUG_MSG("%.6f: end entity (%d)\n", run_state::network_time, is_orig);

	if ( entity == top_level )
		{
		body_length += ((HTTP_Entity*)entity)->BodyLength();
		header_length += ((HTTP_Entity*)entity)->HeaderLength();
		}

	if ( http_end_entity )
		analyzer->EnqueueConnEvent(http_end_entity, analyzer->ConnVal(), val_mgr->Bool(is_orig));

	current_entity = (HTTP_Entity*)entity->Parent();

	if ( entity->Parent() &&
	     entity->Parent()->MIMEContentType() == analyzer::mime::CONTENT_TYPE_MULTIPART )
		{
		content_line->SuppressWeirds(false);
		content_line->SetCRLFAsEOL();
		}

	// It is necessary to call Done when EndEntity is triggered by
	// SubmitAllHeaders (through EndOfData).
	if ( entity == top_level )
		Done();

	else if ( is_orig || MyHTTP_Analyzer()->HTTP_ReplyCode() != 206 )
		{
		HTTP_Entity* he = dynamic_cast<HTTP_Entity*>(entity);

		if ( he && ! he->FileID().empty() )
			file_mgr->EndOfFile(he->FileID());
		else
			file_mgr->EndOfFile(MyHTTP_Analyzer()->GetAnalyzerTag(), MyHTTP_Analyzer()->Conn(),
			                    is_orig);
		}
	}

void HTTP_Message::SubmitHeader(analyzer::mime::MIME_Header* h)
	{
	MyHTTP_Analyzer()->HTTP_Header(is_orig, h);
	}

void HTTP_Message::SubmitAllHeaders(analyzer::mime::MIME_HeaderList& hlist)
	{
	if ( http_all_headers )
		analyzer->EnqueueConnEvent(http_all_headers, analyzer->ConnVal(), val_mgr->Bool(is_orig),
		                           ToHeaderTable(hlist));

	if ( http_content_type )
		analyzer->EnqueueConnEvent(http_content_type, analyzer->ConnVal(), val_mgr->Bool(is_orig),
		                           current_entity->GetContentType(),
		                           current_entity->GetContentSubType());
	}

void HTTP_Message::SubmitTrailingHeaders(analyzer::mime::MIME_HeaderList& /* hlist */)
	{
	// Do nothing for now.  Note that if this ever changes do something
	// which relies on the header list argument, that's currently not
	// populated unless the http_all_headers or mime_all_headers events
	// are being used (so you may need to change that, too).
	}

void HTTP_Message::SubmitData(int len, const char* buf)
	{
	if ( http_entity_data )
		MyHTTP_Analyzer()->HTTP_EntityData(
			is_orig, new String(reinterpret_cast<const u_char*>(buf), len, false));
	}

bool HTTP_Message::RequestBuffer(int* plen, char** pbuf)
	{
	if ( ! entity_data_buffer )
		entity_data_buffer = new char[zeek::detail::http_entity_data_delivery_size];

	*plen = zeek::detail::http_entity_data_delivery_size;
	*pbuf = entity_data_buffer;
	return true;
	}

void HTTP_Message::SubmitAllData()
	{
	// This marks the end of message
	}

void HTTP_Message::SubmitEvent(int event_type, const char* detail)
	{
	const char* category = "";

	switch ( event_type )
		{
		case analyzer::mime::MIME_EVENT_ILLEGAL_FORMAT:
			category = "illegal format";
			break;

		case analyzer::mime::MIME_EVENT_ILLEGAL_ENCODING:
			category = "illegal encoding";
			break;

		case analyzer::mime::MIME_EVENT_CONTENT_GAP:
			category = "content gap";
			break;

		default:
			reporter->AnalyzerError(MyHTTP_Analyzer(), "unrecognized HTTP message event");
			return;
		}

	MyHTTP_Analyzer()->HTTP_Event(category, detail);
	}

void HTTP_Message::SetPlainDelivery(int64_t length)
	{
	content_line->SetPlainDelivery(length);

	if ( length > 0 && BifConst::skip_http_data )
		content_line->SkipBytesAfterThisLine(length);
	}

void HTTP_Message::SetDeliverySize(int64_t length)
	{
	content_line->SetDeliverySize(length);
	}

void HTTP_Message::SkipEntityData()
	{
	if ( current_entity )
		current_entity->SkipBody();
	}

void HTTP_Message::Weird(const char* msg)
	{
	analyzer->Weird(msg);
	}

HTTP_Analyzer::HTTP_Analyzer(Connection* conn)
	: analyzer::tcp::TCP_ApplicationAnalyzer("HTTP", conn)
	{
	num_requests = num_replies = 0;
	num_request_lines = num_reply_lines = 0;
	keep_alive = 0;
	connection_close = 0;

	request_message = reply_message = nullptr;
	request_state = EXPECT_REQUEST_LINE;
	reply_state = EXPECT_REPLY_LINE;

	request_ongoing = 0;

	reply_ongoing = 0;
	reply_code = 0;

	connect_request = false;
	pia = nullptr;
	upgraded = false;
	upgrade_connection = false;
	upgrade_protocol.clear();

	content_line_orig = new analyzer::tcp::ContentLine_Analyzer(conn, true);
	AddSupportAnalyzer(content_line_orig);

	content_line_resp = new analyzer::tcp::ContentLine_Analyzer(conn, false);
	content_line_resp->SetSkipPartial(true);
	AddSupportAnalyzer(content_line_resp);
	}

void HTTP_Analyzer::Done()
	{
	if ( IsFinished() )
		return;

	analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	RequestMade(true, "message interrupted when connection done");
	ReplyMade(true, "message interrupted when connection done");

	delete request_message;
	request_message = nullptr;

	delete reply_message;
	reply_message = nullptr;

	GenStats();

	unanswered_requests = {};

	file_mgr->EndOfFile(GetAnalyzerTag(), Conn(), true);

	/* TODO: this might be nice to have, but reply code is cleared by now.
	if ( HTTP_ReplyCode() != 206 )
	    // multipart/byteranges may span multiple connections
	    file_mgr->EndOfFile(GetAnalyzerTag(), Conn(), false);
	*/
	}

void HTTP_Analyzer::DeliverStream(int len, const u_char* data, bool is_orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, is_orig);

	if ( TCP() && TCP()->IsPartial() )
		return;

	if ( upgraded )
		return;

	if ( pia )
		{
		// There will be a PIA instance if this connection has been identified
		// as a connect proxy.
		ForwardStream(len, data, is_orig);
		return;
		}

	const char* line = reinterpret_cast<const char*>(data);
	const char* end_of_line = line + len;

	analyzer::tcp::ContentLine_Analyzer* content_line = is_orig ? content_line_orig
	                                                            : content_line_resp;

	if ( content_line->IsPlainDelivery() )
		{
		if ( is_orig )
			{
			if ( request_message )
				request_message->Deliver(len, line, false);
			else
				Weird("unexpected_client_HTTP_data");
			}
		else
			{
			if ( reply_message )
				reply_message->Deliver(len, line, false);
			else
				Weird("unexpected_server_HTTP_data");
			}
		return;
		}

	// HTTP_Event("HTTP line", to_string_val(length, line));

	if ( is_orig )
		{
		++num_request_lines;

		switch ( request_state )
			{
			case EXPECT_REQUEST_LINE:
				{
				int res = HTTP_RequestLine(line, end_of_line);

				if ( res < 0 )
					return;

				else if ( res > 0 )
					{
					++num_requests;

					if ( ! keep_alive && num_requests > 1 )
						Weird("unexpected_multiple_HTTP_requests");

					request_state = EXPECT_REQUEST_MESSAGE;
					request_ongoing = 1;
					unanswered_requests.push(request_method);
					HTTP_Request();
					InitHTTPMessage(content_line, request_message, is_orig, HTTP_BODY_MAYBE, len);
					}

				else
					{
					if ( ! RequestExpected() )
						HTTP_Event("crud_trailing_HTTP_request",
						           analyzer::mime::to_string_val(line, end_of_line));
					else
						{
						// We do see HTTP requests with a
						// trailing EOL that's not accounted
						// for by the content-length. This
						// will lead to a call to this method
						// with len==0 while we are expecting
						// a new request. Since HTTP servers
						// handle such requests gracefully,
						// we should do so as well.
						if ( len == 0 )
							Weird("empty_http_request");
						else
							{
							AnalyzerViolation("not a http request line");
							request_state = EXPECT_REQUEST_NOTHING;
							}
						}
					}
				}
				break;

			case EXPECT_REQUEST_MESSAGE:
				request_message->Deliver(len, line, true);
				break;

			case EXPECT_REQUEST_TRAILER:
				break;

			case EXPECT_REQUEST_NOTHING:
				break;
			}
		}
	else
		{ // HTTP reply
		switch ( reply_state )
			{
			case EXPECT_REPLY_LINE:
				if ( HTTP_ReplyLine(line, end_of_line) )
					{
					++num_replies;

					if ( ! unanswered_requests.empty() )
						AnalyzerConfirmation();

					reply_state = EXPECT_REPLY_MESSAGE;
					reply_ongoing = 1;

					HTTP_Reply();

					if ( connect_request && reply_code != 200 )
						// Request failed, do not set up tunnel.
						connect_request = false;

					InitHTTPMessage(content_line, reply_message, is_orig, ExpectReplyMessageBody(),
					                len);
					}
				else
					{
					if ( line != end_of_line )
						{
						AnalyzerViolation("not a http reply line");
						reply_state = EXPECT_REPLY_NOTHING;
						}
					}

				break;

			case EXPECT_REPLY_MESSAGE:
				reply_message->Deliver(len, line, true);

				if ( connect_request && len == 0 )
					{
					// End of message header reached, set up
					// tunnel decapsulation.
					pia = new analyzer::pia::PIA_TCP(Conn());

					if ( AddChildAnalyzer(pia) )
						{
						pia->FirstPacket(true, nullptr);
						pia->FirstPacket(false, nullptr);

						// This connection has transitioned to no longer
						// being http and the content line support analyzers
						// need to be removed.
						RemoveSupportAnalyzer(content_line_orig);
						RemoveSupportAnalyzer(content_line_resp);
						}

					else
						// AddChildAnalyzer() will have deleted PIA.
						pia = nullptr;
					}

				break;

			case EXPECT_REPLY_TRAILER:
				break;

			case EXPECT_REPLY_NOTHING:
				break;
			}
		}
	}

void HTTP_Analyzer::Undelivered(uint64_t seq, int len, bool is_orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, is_orig);

	// DEBUG_MSG("Undelivered from %"PRIu64": %d bytes\n", seq, length);

	HTTP_Message* msg = is_orig ? request_message : reply_message;

	analyzer::tcp::ContentLine_Analyzer* content_line = is_orig ? content_line_orig
	                                                            : content_line_resp;

	if ( ! content_line->IsSkippedContents(seq, len) )
		{
		if ( msg )
			msg->SubmitEvent(analyzer::mime::MIME_EVENT_CONTENT_GAP,
			                 util::fmt("seq=%" PRIu64 ", len=%d", seq, len));
		}

	// Check if the content gap falls completely within a message body
	if ( msg && msg->Undelivered(len) )
		// If so, we are safe to skip the content and go on parsing
		return;

	// Otherwise stop parsing the connection
	if ( is_orig )
		{
		// Stop parsing reply messages too, because whether a
		// reply contains a body may depend on knowing the
		// request method

		RequestMade(true, "message interrupted by a content gap");
		ReplyMade(true, "message interrupted by a content gap");

		content_line->SetSkipDeliveries(true);
		}
	else
		{
		ReplyMade(true, "message interrupted by a content gap");
		content_line->SetSkipDeliveries(true);
		}
	}

void HTTP_Analyzer::EndpointEOF(bool is_orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);

	// DEBUG_MSG("%.6f eof\n", run_state::network_time);

	if ( is_orig )
		RequestMade(false, "message ends as connection contents are completely delivered");
	else
		ReplyMade(false, "message ends as connection contents are completely delivered");
	}

void HTTP_Analyzer::ConnectionFinished(bool half_finished)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::ConnectionFinished(half_finished);

	// DEBUG_MSG("%.6f connection finished\n", run_state::network_time);
	RequestMade(true, "message ends as connection is finished");
	ReplyMade(true, "message ends as connection is finished");
	}

void HTTP_Analyzer::ConnectionReset()
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::ConnectionReset();

	RequestMade(true, "message interrupted by RST");
	ReplyMade(true, "message interrupted by RST");
	}

void HTTP_Analyzer::PacketWithRST()
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::PacketWithRST();

	RequestMade(true, "message interrupted by RST");
	ReplyMade(true, "message interrupted by RST");
	}

void HTTP_Analyzer::GenStats()
	{
	if ( http_stats )
		{
		static auto http_stats_rec = id::find_type<RecordType>("http_stats_rec");
		auto r = make_intrusive<RecordVal>(http_stats_rec);
		r->Assign(0, num_requests);
		r->Assign(1, num_replies);
		r->Assign(2, request_version.ToDouble());
		r->Assign(3, reply_version.ToDouble());

		// DEBUG_MSG("%.6f http_stats\n", run_state::network_time);
		EnqueueConnEvent(http_stats, ConnVal(), std::move(r));
		}
	}

const char* HTTP_Analyzer::PrefixMatch(const char* line, const char* end_of_line,
                                       const char* prefix)
	{
	while ( *prefix && line < end_of_line && *prefix == *line )
		{
		++prefix;
		++line;
		}

	if ( *prefix )
		// It didn't match.
		return nullptr;

	return line;
	}

const char* HTTP_Analyzer::PrefixWordMatch(const char* line, const char* end_of_line,
                                           const char* prefix)
	{
	if ( (line = PrefixMatch(line, end_of_line, prefix)) == nullptr )
		return nullptr;

	const char* orig_line = line;
	line = util::skip_whitespace(line, end_of_line);

	if ( line == orig_line )
		// Word didn't end at prefix.
		return nullptr;

	return line;
	}

static bool is_HTTP_token_char(char c)
	{
	return c > 31 && c != 127 && // CTL per RFC 2616.
	       c != ' ' && c != '\t' && // Separators.
	       c != '(' && c != ')' && c != '<' && c != '>' && c != '@' && c != ',' && c != ';' &&
	       c != ':' && c != '\\' && c != '"' && c != '/' && c != '[' && c != ']' && c != '?' &&
	       c != '=' && c != '{' && c != '}';
	}

static const char* get_HTTP_token(const char* s, const char* e)
	{
	while ( s < e && is_HTTP_token_char(*s) )
		++s;

	return s;
	}

int HTTP_Analyzer::HTTP_RequestLine(const char* line, const char* end_of_line)
	{
	const char* rest = nullptr;
	const char* end_of_method = get_HTTP_token(line, end_of_line);

	if ( end_of_method == line )
		{
		// something went wrong with get_HTTP_token
		// perform a weak test to see if the string "HTTP/"
		// is found at the end of the RequestLine
		if ( end_of_line - 9 >= line && strncasecmp(end_of_line - 9, " HTTP/", 6) == 0 )
			goto bad_http_request_with_version;

		goto error;
		}

	rest = util::skip_whitespace(end_of_method, end_of_line);

	if ( rest == end_of_method )
		goto error;

	if ( ! ParseRequest(rest, end_of_line) )
		{
		reporter->AnalyzerError(this, "HTTP ParseRequest failed");
		return -1;
		}

	request_method = make_intrusive<StringVal>(end_of_method - line, line);

	Conn()->Match(zeek::detail::Rule::HTTP_REQUEST,
	              (const u_char*)unescaped_URI->AsString()->Bytes(),
	              unescaped_URI->AsString()->Len(), true, true, true, true);

	return 1;

bad_http_request_with_version:
	Weird("bad_HTTP_request_with_version");
	return 0;

error:
	Weird("bad_HTTP_request");
	return 0;
	}

bool HTTP_Analyzer::ParseRequest(const char* line, const char* end_of_line)
	{
	const char* end_of_uri;
	const char* version_start;
	const char* version_end;

	for ( end_of_uri = line; end_of_uri < end_of_line; ++end_of_uri )
		{
		if ( ! is_reserved_URI_char(*end_of_uri) && ! is_unreserved_URI_char(*end_of_uri) &&
		     *end_of_uri != '%' )
			break;
		}

	if ( end_of_uri >= end_of_line && PrefixMatch(line, end_of_line, "HTTP/") )
		{
		Weird("missing_HTTP_uri");
		end_of_uri = line; // Leave URI empty.
		}

	for ( version_start = end_of_uri; version_start < end_of_line; ++version_start )
		{
		end_of_uri = version_start;
		version_start = util::skip_whitespace(version_start, end_of_line);
		if ( PrefixMatch(version_start, end_of_line, "HTTP/") )
			break;
		}

	if ( version_start >= end_of_line )
		{
		// If no version is found
		SetVersion(&request_version, {0, 9});
		}
	else
		{
		if ( version_start + 8 <= end_of_line )
			{
			version_start += 5; // "HTTP/"
			SetVersion(&request_version, HTTP_Version(end_of_line - version_start, version_start));

			version_end = version_start + 3;
			if ( util::skip_whitespace(version_end, end_of_line) != end_of_line )
				HTTP_Event("crud after HTTP version is ignored",
				           analyzer::mime::to_string_val(line, end_of_line));
			}
		else
			HTTP_Event("bad_HTTP_version", analyzer::mime::to_string_val(line, end_of_line));
		}

	// NormalizeURI(line, end_of_uri);

	request_URI = make_intrusive<StringVal>(end_of_uri - line, line);
	unescaped_URI = make_intrusive<StringVal>(
		unescape_URI((const u_char*)line, (const u_char*)end_of_uri, this));

	return true;
	}

// Only recognize [0-9][.][0-9].
HTTP_Analyzer::HTTP_VersionNumber HTTP_Analyzer::HTTP_Version(int len, const char* data)
	{
	if ( len >= 3 && data[0] >= '0' && data[0] <= '9' && data[1] == '.' && data[2] >= '0' &&
	     data[2] <= '9' )
		{
		uint8_t major = data[0] - '0';
		uint8_t minor = data[2] - '0';
		return {major, minor};
		}
	else
		{
		HTTP_Event("bad_HTTP_version", analyzer::mime::to_string_val(len, data));
		return {};
		}
	}

void HTTP_Analyzer::SetVersion(HTTP_VersionNumber* version, HTTP_VersionNumber new_version)
	{
	if ( *version == HTTP_VersionNumber{} )
		*version = new_version;

	else if ( *version != new_version )
		Weird("HTTP_version_mismatch");

	if ( version->major > 1 || (version->major == 1 && version->minor > 0) )
		keep_alive = 1;
	}

void HTTP_Analyzer::HTTP_Event(const char* category, const char* detail)
	{
	HTTP_Event(category, make_intrusive<StringVal>(detail));
	}

void HTTP_Analyzer::HTTP_Event(const char* category, StringValPtr detail)
	{
	if ( http_event )
		// DEBUG_MSG("%.6f http_event\n", run_state::network_time);
		EnqueueConnEvent(http_event, ConnVal(), make_intrusive<StringVal>(category),
		                 std::move(detail));
	}

StringValPtr HTTP_Analyzer::TruncateURI(const StringValPtr& uri)
	{
	const String* str = uri->AsString();

	if ( zeek::detail::truncate_http_URI >= 0 && str->Len() > zeek::detail::truncate_http_URI )
		{
		u_char* s = new u_char[zeek::detail::truncate_http_URI + 4];
		memcpy(s, str->Bytes(), zeek::detail::truncate_http_URI);
		memcpy(s + zeek::detail::truncate_http_URI, "...", 4);
		return zeek::make_intrusive<zeek::StringVal>(
			new zeek::String(true, s, zeek::detail::truncate_http_URI + 3));
		}
	else
		return uri;
	}

void HTTP_Analyzer::HTTP_Request()
	{
	AnalyzerConfirmation();

	const char* method = (const char*)request_method->AsString()->Bytes();
	int method_len = request_method->AsString()->Len();

	if ( strncasecmp(method, "CONNECT", method_len) == 0 )
		connect_request = true;

	if ( http_request )
		// DEBUG_MSG("%.6f http_request\n", run_state::network_time);
		EnqueueConnEvent(http_request, ConnVal(), request_method, TruncateURI(request_URI),
		                 TruncateURI(unescaped_URI),
		                 make_intrusive<StringVal>(util::fmt("%.1f", request_version.ToDouble())));
	}

void HTTP_Analyzer::HTTP_Reply()
	{
	if ( http_reply )
		EnqueueConnEvent(http_reply, ConnVal(),
		                 make_intrusive<StringVal>(util::fmt("%.1f", reply_version.ToDouble())),
		                 val_mgr->Count(reply_code),
		                 reply_reason_phrase ? reply_reason_phrase
		                                     : make_intrusive<StringVal>("<empty>"));
	else
		reply_reason_phrase = nullptr;
	}

void HTTP_Analyzer::RequestMade(bool interrupted, const char* msg)
	{
	if ( ! request_ongoing )
		return;

	request_ongoing = 0;

	if ( request_message )
		request_message->Done(interrupted, msg);

	// DEBUG_MSG("%.6f request made\n", run_state::network_time);

	request_method = nullptr;
	unescaped_URI = nullptr;
	request_URI = nullptr;

	num_request_lines = 0;

	if ( interrupted )
		request_state = EXPECT_REQUEST_NOTHING;
	else
		request_state = EXPECT_REQUEST_LINE;
	}

void HTTP_Analyzer::ReplyMade(bool interrupted, const char* msg)
	{
	if ( ! reply_ongoing )
		return;

	reply_ongoing = 0;

	// DEBUG_MSG("%.6f reply made\n", run_state::network_time);

	if ( reply_message )
		reply_message->Done(interrupted, msg);

	// 1xx replies do not indicate the final response to a request,
	// so don't pop an unanswered request in that case.
	if ( (reply_code < 100 || reply_code >= 200) && ! unanswered_requests.empty() )
		unanswered_requests.pop();

	if ( reply_reason_phrase )
		reply_reason_phrase = nullptr;

	// unanswered requests = 1 because there is no pop after 101.
	if ( reply_code == 101 && unanswered_requests.size() == 1 && upgrade_connection &&
	     upgrade_protocol.size() )
		{
		// Upgraded connection that switches immediately - e.g. websocket.
		upgraded = true;
		RemoveSupportAnalyzer(content_line_orig);
		RemoveSupportAnalyzer(content_line_resp);

		if ( http_connection_upgrade )
			EnqueueConnEvent(http_connection_upgrade, ConnVal(),
			                 make_intrusive<StringVal>(upgrade_protocol));
		}

	reply_code = 0;
	upgrade_connection = false;
	upgrade_protocol.clear();

	if ( interrupted || upgraded )
		reply_state = EXPECT_REPLY_NOTHING;
	else
		reply_state = EXPECT_REPLY_LINE;
	}

void HTTP_Analyzer::RequestClash(Val* /* clash_val */)
	{
	Weird("multiple_HTTP_request_elements");

	// Flush out old values.
	RequestMade(true, "request clash");
	}

const String* HTTP_Analyzer::UnansweredRequestMethod()
	{
	return unanswered_requests.empty() ? nullptr : unanswered_requests.front()->AsString();
	}

int HTTP_Analyzer::HTTP_ReplyLine(const char* line, const char* end_of_line)
	{
	const char* rest;

	if ( ! (rest = PrefixMatch(line, end_of_line, "HTTP/")) )
		{
		// ##TODO: some server replies with an HTML document
		// without a status line and a MIME header, when the
		// request is malformed.
		HTTP_Event("bad_HTTP_reply", analyzer::mime::to_string_val(line, end_of_line));
		return 0;
		}

	SetVersion(&reply_version, HTTP_Version(end_of_line - rest, rest));

	for ( ; rest < end_of_line; ++rest )
		if ( analyzer::mime::is_lws(*rest) )
			break;

	if ( rest >= end_of_line )
		{
		HTTP_Event("HTTP_reply_code_missing", analyzer::mime::to_string_val(line, end_of_line));
		return 0;
		}

	rest = util::skip_whitespace(rest, end_of_line);

	if ( rest + 3 > end_of_line )
		{
		HTTP_Event("HTTP_reply_code_missing", analyzer::mime::to_string_val(line, end_of_line));
		return 0;
		}

	reply_code = HTTP_ReplyCode(rest);

	for ( rest += 3; rest < end_of_line; ++rest )
		if ( analyzer::mime::is_lws(*rest) )
			break;

	if ( rest >= end_of_line )
		{
		HTTP_Event("HTTP_reply_reason_phrase_missing",
		           analyzer::mime::to_string_val(line, end_of_line));
		// Tolerate missing reason phrase?
		return 1;
		}

	rest = util::skip_whitespace(rest, end_of_line);
	reply_reason_phrase = make_intrusive<StringVal>(end_of_line - rest, (const char*)rest);

	return 1;
	}

int HTTP_Analyzer::HTTP_ReplyCode(const char* code_str)
	{
	if ( isdigit(code_str[0]) && isdigit(code_str[1]) && isdigit(code_str[2]) )
		return (code_str[0] - '0') * 100 + (code_str[1] - '0') * 10 + (code_str[2] - '0');
	else
		return 0;
	}

int HTTP_Analyzer::ExpectReplyMessageBody()
	{
	// RFC 2616:
	//
	//     For response messages, whether or not a message-body is included with
	//     a message is dependent on both the request method and the response
	//     status code (section 6.1.1). All responses to the HEAD request method
	//     MUST NOT include a message-body, even though the presence of entity-
	//     header fields might lead one to believe they do. All 1xx
	//     (informational), 204 (no content), and 304 (not modified) responses
	//     MUST NOT include a message-body. All other responses do include a
	//     message-body, although it MAY be of zero length.

	const String* method = UnansweredRequestMethod();

	if ( method && strncasecmp((const char*)(method->Bytes()), "HEAD", method->Len()) == 0 )
		return HTTP_BODY_NOT_EXPECTED;

	if ( (reply_code >= 100 && reply_code < 200) || reply_code == 204 || reply_code == 304 )
		return HTTP_BODY_NOT_EXPECTED;

	return HTTP_BODY_EXPECTED;
	}

void HTTP_Analyzer::HTTP_Header(bool is_orig, analyzer::mime::MIME_Header* h)
	{
	// To be "liberal", we only look at "keep-alive" on the client
	// side, and if seen assume the connection to be persistent.
	// This seems fairly safe - at worst, the client does indeed
	// send additional requests, and the server ignores them.
	if ( is_orig && analyzer::mime::istrequal(h->get_name(), "connection") )
		{
		if ( analyzer::mime::istrequal(h->get_value_token(), "keep-alive") )
			keep_alive = 1;
		}

	if ( ! is_orig && analyzer::mime::istrequal(h->get_name(), "connection") )
		{
		if ( analyzer::mime::istrequal(h->get_value_token(), "close") )
			connection_close = 1;
		else if ( analyzer::mime::istrequal(h->get_value_token(), "upgrade") )
			upgrade_connection = true;
		}

	if ( ! is_orig && analyzer::mime::istrequal(h->get_name(), "upgrade") )
		upgrade_protocol.assign(h->get_value_token().data, h->get_value_token().length);

	if ( http_header )
		{
		zeek::detail::Rule::PatternType rule = is_orig ? zeek::detail::Rule::HTTP_REQUEST_HEADER
		                                               : zeek::detail::Rule::HTTP_REPLY_HEADER;

		data_chunk_t hd_name = h->get_name();
		data_chunk_t hd_value = h->get_value();

		Conn()->Match(rule, (const u_char*)hd_name.data, hd_name.length, is_orig, true, false,
		              true);
		Conn()->Match(rule, (const u_char*)": ", 2, is_orig, false, false, false);
		Conn()->Match(rule, (const u_char*)hd_value.data, hd_value.length, is_orig, false, true,
		              false);

		if ( DEBUG_http )
			DEBUG_MSG("%.6f http_header\n", run_state::network_time);

		auto upper_hn = analyzer::mime::to_string_val(h->get_name());
		upper_hn->ToUpper();

		EnqueueConnEvent(http_header, ConnVal(), val_mgr->Bool(is_orig),
		                 analyzer::mime::to_string_val(h->get_name()), std::move(upper_hn),
		                 analyzer::mime::to_string_val(h->get_value()));
		}
	}

void HTTP_Analyzer::HTTP_EntityData(bool is_orig, String* entity_data)
	{
	if ( http_entity_data )
		EnqueueConnEvent(http_entity_data, ConnVal(), val_mgr->Bool(is_orig),
		                 val_mgr->Count(entity_data->Len()),
		                 make_intrusive<StringVal>(entity_data));
	else
		delete entity_data;
	}

// Calls request/reply done
void HTTP_Analyzer::HTTP_MessageDone(bool is_orig, HTTP_Message* /* message */)
	{
	if ( is_orig )
		RequestMade(false, "message ends normally");
	else
		ReplyMade(false, "message ends normally");
	}

void HTTP_Analyzer::InitHTTPMessage(analyzer::tcp::ContentLine_Analyzer* cl, HTTP_Message*& message,
                                    bool is_orig, int expect_body, int64_t init_header_length)
	{
	if ( message )
		{
		if ( ! message->Finished() )
			Weird("HTTP_overlapping_messages");

		delete message;
		}

	// DEBUG_MSG("%.6f init http message\n", run_state::network_time);
	message = new HTTP_Message(this, cl, is_orig, expect_body, init_header_length);
	}

void HTTP_Analyzer::SkipEntityData(bool is_orig)
	{
	HTTP_Message* msg = is_orig ? request_message : reply_message;

	if ( msg )
		msg->SkipEntityData();
	}

bool is_reserved_URI_char(unsigned char ch)
	{ // see RFC 3986 (definition of URI)
	return strchr(":/?#[]@!$&'()*+,;=", ch) != 0;
	}

bool is_unreserved_URI_char(unsigned char ch)
	{ // see RFC 3986 (definition of URI)
	return isalnum(ch) != 0 || strchr("-_.!~*\'()", ch) != 0;
	}

void escape_URI_char(unsigned char ch, unsigned char*& p)
	{
	*p++ = '%';
	*p++ = util::encode_hex((ch >> 4) & 0xf);
	*p++ = util::encode_hex(ch & 0xf);
	}

String* unescape_URI(const u_char* line, const u_char* line_end, analyzer::Analyzer* analyzer)
	{
	byte_vec decoded_URI = new u_char[line_end - line + 1];
	byte_vec URI_p = decoded_URI;

	while ( line < line_end )
		{
		if ( *line == '%' )
			{
			++line;

			if ( line == line_end )
				{
				*URI_p++ = '%';
				if ( analyzer )
					analyzer->Weird("illegal_%_at_end_of_URI");
				break;
				}

			else if ( line + 1 == line_end )
				{
				// % + one character at end of line. Log weird
				// and just add to unescpaped URI.
				*URI_p++ = '%';
				*URI_p++ = *line;
				if ( analyzer )
					analyzer->Weird("partial_escape_at_end_of_URI");
				break;
				}

			else if ( *line == '%' )
				{
				// Double '%' might be either due to
				// software bug, or more likely, an
				// evasion (e.g. used by Nimda).
				// *URI_p++ = '%';
				if ( analyzer )
					analyzer->Weird("double_%_in_URI");
				--line; // ignore the first '%'
				}

			else if ( isxdigit(line[0]) && isxdigit(line[1]) )
				{
				*URI_p++ = (util::decode_hex(line[0]) << 4) + util::decode_hex(line[1]);
				++line; // place line at the last hex digit
				}

			else if ( line_end - line >= 5 && line[0] == 'u' && isxdigit(line[1]) &&
			          isxdigit(line[2]) && isxdigit(line[3]) && isxdigit(line[4]) )
				{
				// Decode escaping like this: %u00AE
				// The W3C rejected escaping this way, and
				// there is no RFC that specifies it.
				// Apparently there is some software doing
				// this sort of 4 byte unicode encoding anyway.
				// Likely causing an increase in it's use is
				// the third edition of the ECMAScript spec
				// having functions for encoding and decoding
				// data in this format.

				// If the first byte is null, let's eat it.
				// It could just be ASCII encoded into this
				// unicode escaping structure.
				if ( ! (line[1] == '0' && line[2] == '0') )
					*URI_p++ = (util::decode_hex(line[1]) << 4) + util::decode_hex(line[2]);

				*URI_p++ = (util::decode_hex(line[3]) << 4) + util::decode_hex(line[4]);

				line += 4;
				}

			else
				{
				if ( analyzer )
					analyzer->Weird("unescaped_%_in_URI");
				*URI_p++ = '%'; // put back initial '%'
				*URI_p++ = *line; // take char w/o interp.
				}
			}

		else
			*URI_p++ = *line;

		++line;
		}

	URI_p[0] = 0;

	return new String(true, decoded_URI, URI_p - decoded_URI);
	}

	} // namespace zeek::analyzer::http
