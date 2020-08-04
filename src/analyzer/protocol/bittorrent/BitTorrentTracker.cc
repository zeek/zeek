// This code contributed by Nadi Sarrar.

#include "BitTorrentTracker.h"
#include "analyzer/protocol/tcp/TCP_Reassembler.h"

#include "events.bif.h"

#include <sys/types.h>
#include <regex.h>

#include <algorithm>

# define FMT_INT "%" PRId64
# define FMT_UINT "%" PRIu64

namespace zeek::analyzer::bittorrent {

static zeek::TableTypePtr bt_tracker_headers;
static zeek::RecordTypePtr bittorrent_peer;
static zeek::TableTypePtr bittorrent_peer_set;
static zeek::RecordTypePtr bittorrent_benc_value;
static zeek::TableTypePtr bittorrent_benc_dir;

BitTorrentTracker_Analyzer::BitTorrentTracker_Analyzer(zeek::Connection* c)
: zeek::analyzer::tcp::TCP_ApplicationAnalyzer("BITTORRENTTRACKER", c)
	{
	if ( ! bt_tracker_headers )
		{
		bt_tracker_headers =
			zeek::id::find_type<zeek::TableType>("bt_tracker_headers");
		bittorrent_peer =
			zeek::id::find_type<zeek::RecordType>("bittorrent_peer");
		bittorrent_peer_set =
			zeek::id::find_type<zeek::TableType>("bittorrent_peer_set");
		bittorrent_benc_value =
			zeek::id::find_type<zeek::RecordType>("bittorrent_benc_value");
		bittorrent_benc_dir =
			zeek::id::find_type<zeek::TableType>("bittorrent_benc_dir");
		}

	keep_alive = false;

	req_state = detail::BTT_REQ_GET;
	req_buf[sizeof(req_buf) - 1] = 0;
	req_buf_pos = req_buf;
	req_buf_len = 0;
	req_val_uri = nullptr;
	req_val_headers = new zeek::TableVal(bt_tracker_headers);

	res_state = detail::BTT_RES_STATUS;
	res_allow_blank_line = false;
	res_buf[sizeof(res_buf) - 1] = 0;
	res_buf_pos = res_buf;
	res_buf_len = 0;
	res_status = 0;
	res_val_headers = new zeek::TableVal(bt_tracker_headers);
	res_val_peers = new zeek::TableVal(bittorrent_peer_set);
	res_val_benc = new zeek::TableVal(bittorrent_benc_dir);

	InitBencParser();

	stop_orig = false;
	stop_resp = false;
	}

BitTorrentTracker_Analyzer::~BitTorrentTracker_Analyzer()
	{
	Unref(req_val_uri);
	Unref(req_val_headers);

	Unref(res_val_headers);
	Unref(res_val_peers);
	Unref(res_val_benc);

	benc_stack.clear();
	benc_count.clear();
	}

void BitTorrentTracker_Analyzer::Done()
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Done();
	}

void BitTorrentTracker_Analyzer::DeliverStream(int len, const u_char* data,
						bool orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());

	if ( TCP()->IsPartial() )
		// punt on partial.
		return;

	if ( orig )
		ClientRequest(len, data);
	else
		ServerReply(len, data);
	}

void BitTorrentTracker_Analyzer::ClientRequest(int len, const u_char* data)
	{
	if ( stop_orig )
		return;

	if ( req_buf_len + len > sizeof(req_buf) - 1 )
		{
		ProtocolViolation("BitTorrentTracker: request message too long");
		stop_orig = true;
		return;
		}

	memcpy(&req_buf[req_buf_len], data, len);
	req_buf_len += len;
	req_buf[req_buf_len] = 0;

	while ( req_buf_pos < req_buf + req_buf_len )
		{
		char* lf = strchr(req_buf_pos, '\n');
		if ( ! lf )
			break;
		*lf = 0;

		char* cr = strrchr(req_buf_pos, '\r');
		if ( cr )
			*cr = 0;

		if ( ! ParseRequest(req_buf_pos) )
			return;

		req_buf_pos = lf + 1;

		if ( req_state == detail::BTT_REQ_DONE && keep_alive )
			{
			req_state = detail::BTT_REQ_GET;
			req_buf_len -= (req_buf_pos - req_buf);
			memmove(req_buf, req_buf_pos, req_buf_len);
			req_buf_pos = req_buf;
			req_val_headers = new zeek::TableVal(bt_tracker_headers);
			}
		}
	}

void BitTorrentTracker_Analyzer::ServerReply(int len, const u_char* data)
	{
	if ( stop_resp )
		return;

	if ( res_state == detail::BTT_RES_DONE )
		// We are done already, i.e. state != 200.
		return;

	if ( res_buf_len + len > sizeof(res_buf) - 1 )
		{
		ProtocolViolation("BitTorrentTracker: response message too long");
		stop_resp = true;
		return;
		}

	memcpy(&res_buf[res_buf_len], data, len);
	res_buf_len += len;
	res_buf[res_buf_len] = 0;

	while ( true )
		{
		while ( res_state != detail::BTT_RES_BODY &&
			res_buf_pos < res_buf + res_buf_len )
			{
			char* lf = strchr(res_buf_pos, '\n');
			if ( ! lf )
				break;
			*lf = 0;

			char* cr = strrchr(res_buf_pos, '\r');
			if ( cr )
				*cr = 0;

			if ( ! ParseResponse(res_buf_pos) )
				return;

			res_buf_pos = lf + 1;
			}

		if ( res_state != detail::BTT_RES_BODY ||
		     res_buf_pos >= res_buf + res_buf_len )
			break;

		ResponseBody();

		if ( res_state != detail::BTT_RES_DONE ||
		     res_status != 200 || ! keep_alive )
			break;

		res_state = detail::BTT_RES_STATUS;
		res_allow_blank_line = true;
		res_buf_len -= res_buf_pos - res_buf;
		memmove(res_buf, res_buf_pos, res_buf_len);
		res_buf_pos = res_buf;
		res_status = 0;

		res_val_headers = new zeek::TableVal(bt_tracker_headers);
		res_val_peers = new zeek::TableVal(bittorrent_peer_set);
		res_val_benc = new zeek::TableVal(bittorrent_benc_dir);

		InitBencParser();
		}
	}

void BitTorrentTracker_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);

	ProtocolViolation("BitTorrentTracker: cannot recover from content gap");

	if ( orig )
		stop_orig = true;
	else
		stop_resp = true;
	}

void BitTorrentTracker_Analyzer::EndpointEOF(bool is_orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	}

void BitTorrentTracker_Analyzer::InitBencParser(void)
	{
	benc_stack.clear();
	benc_count.clear();

	benc_state = detail::BENC_STATE_EMPTY;
	benc_raw = nullptr;
	benc_raw_type = detail::BENC_TYPE_NONE;
	benc_raw_len = 0;
	benc_key = nullptr;
	benc_key_len = 0;
	benc_strlen = nullptr;
	benc_str = nullptr;
	benc_str_len = 0;
	benc_str_have = 0;
	benc_int = nullptr;
	benc_int_val = 0;
	}

void BitTorrentTracker_Analyzer::DeliverWeird(const char* msg, bool orig)
	{
	if ( bt_tracker_weird )
		EnqueueConnEvent(bt_tracker_weird,
			ConnVal(),
			zeek::val_mgr->Bool(orig),
			zeek::make_intrusive<zeek::StringVal>(msg)
		);
	}

bool BitTorrentTracker_Analyzer::ParseRequest(char* line)
	{
	static bool initialized = false;
	static regex_t r_get, r_get_end, r_hdr;

	if ( ! initialized )
		{
		regcomp(&r_get, "^GET[ \t]+", REG_EXTENDED | REG_ICASE);
		regcomp(&r_get_end, "[ \t]+HTTP/[0123456789.]+$",
			REG_EXTENDED | REG_ICASE);
		regcomp(&r_hdr, "^[^: \t]+:[ ]*", REG_EXTENDED | REG_ICASE);
		initialized = true;
		}

	switch ( req_state ) {
	case detail::BTT_REQ_GET:
		{
		regmatch_t match[1];
		if ( regexec(&r_get, line, 1, match, 0) )
			{
			ProtocolViolation("BitTorrentTracker: invalid HTTP GET");
			stop_orig = true;
			return false;
			}

		regmatch_t match_end[1];
		if ( ! regexec(&r_get_end, line, 1, match_end, 0) )
			{
			if ( match_end[0].rm_so <= match[0].rm_eo )
				{
				ProtocolViolation("BitTorrentTracker: invalid HTTP GET");
				stop_orig = true;
				return false;
				}

			keep_alive = (line[match_end[0].rm_eo - 1] == '1');
			line[match_end[0].rm_so] = 0;
			}

		RequestGet(&line[match[0].rm_eo]);

		req_state = detail::BTT_REQ_HEADER;
		}
		break;

	case detail::BTT_REQ_HEADER:
		{
		if ( ! *line )
			{
			EmitRequest();
			req_state = detail::BTT_REQ_DONE;
			break;
			}

		regmatch_t match[1];
		if ( regexec(&r_hdr, line, 1, match, 0) )
			{
			ProtocolViolation("BitTorrentTracker: invalid HTTP request header");
			stop_orig = true;
			return false;
			}

		*strchr(line, ':') = 0;	// this cannot fail - see regex_hdr
		RequestHeader(line, &line[match[0].rm_eo]);
		}
		break;

	case detail::BTT_REQ_DONE:
		if ( *line )
			{
			auto msg = fmt("Got post request data: %s\n", line);
			Weird("bittorrent_tracker_data_post_request", msg);
			DeliverWeird(msg, true);
			}
		break;

	default:
		// Make the compiler happy.
		break;
	}

	return true;
	}

void BitTorrentTracker_Analyzer::RequestGet(char* uri)
	{
	req_val_uri = new zeek::StringVal(uri);
	}

void BitTorrentTracker_Analyzer::EmitRequest(void)
	{
	ProtocolConfirmation();

	if ( bt_tracker_request )
		EnqueueConnEvent(bt_tracker_request,
		                 ConnVal(),
		                 zeek::IntrusivePtr{zeek::AdoptRef{}, req_val_uri},
		                 zeek::IntrusivePtr{zeek::AdoptRef{}, req_val_headers}
		);

	req_val_uri = nullptr;
	req_val_headers = nullptr;
	}

bool BitTorrentTracker_Analyzer::ParseResponse(char* line)
	{
	static bool initialized = false;
	static regex_t r_stat, r_hdr;

	if ( ! initialized )
		{
		regcomp(&r_stat, "^HTTP/[0123456789.]* ",
			REG_EXTENDED | REG_ICASE);
		regcomp(&r_hdr, "^[^: \t]+:[ ]*", REG_EXTENDED | REG_ICASE);
		initialized = true;
		}

	switch ( res_state ) {
	case detail::BTT_RES_STATUS:
		{
		if ( res_allow_blank_line && ! *line )
			{
			// There may be an empty line after the bencoded
			// directory, if this is a keep-alive connection.
			// Ignore it.
			res_allow_blank_line = false;
			break;
			}

		regmatch_t match[1];
		if ( regexec(&r_stat, line, 1, match, 0) )
			{
			ProtocolViolation("BitTorrentTracker: invalid HTTP status");
			stop_resp = true;
			return false;
			}

		ResponseStatus(&line[match[0].rm_eo]);
		res_state = detail::BTT_RES_HEADER;
		}
		break;

	case detail::BTT_RES_HEADER:
		if ( ! *line )
			{
			if ( res_status != 200 )
				{
				if ( bt_tracker_response_not_ok )
					EnqueueConnEvent(
						bt_tracker_response_not_ok,
						ConnVal(),
						zeek::val_mgr->Count(res_status),
						zeek::IntrusivePtr{zeek::AdoptRef{}, res_val_headers}
					);
				res_val_headers = nullptr;
				res_buf_pos = res_buf + res_buf_len;
				res_state = detail::BTT_RES_DONE;
				}
			else
				res_state = detail::BTT_RES_BODY;

			break;
			}

		{
		regmatch_t match[1];
		if ( regexec(&r_hdr, line, 1, match, 0) )
			{
			ProtocolViolation("BitTorrentTracker: invalid HTTP response header");
			stop_resp = true;
			return false;
			}

		*strchr(line, ':') = 0;	// this cannot fail - see regex_hdr
		ResponseHeader(line, &line[match[0].rm_eo]);
		}
		break;

	default:
		// Make the compiler happy.
		break;
	}

	return true;
	}

void BitTorrentTracker_Analyzer::ResponseStatus(char* status)
	{
	if ( sscanf(status, FMT_UINT, &res_status) != 1 )
		res_status = 0;
	}

void BitTorrentTracker_Analyzer::ParseHeader(char* name, char* value,
						bool is_request)
	{
	if ( ! strcasecmp(name, "connection") )
		{
		if ( ! strcasecmp(value, "close") )
			keep_alive = false;
		else
			keep_alive = true;
		}

#ifdef BTTRACKER_STORE_HEADERS
	zeek::StringVal* name_ = new zeek::StringVal(name);
	zeek::StringVal* value_ = new zeek::StringVal(value);

	(is_request ? req_val_headers : res_val_headers)->Assign(name_, value_);
	Unref(name_);
#endif
	}

void BitTorrentTracker_Analyzer::ResponseBenc(int name_len, char* name,
                                              detail::BTT_BencTypes type,
                                              int value_len, char* value)
	{
	if ( name_len == 5 && ! strncmp(name, "peers", 5) )
		{
		for ( char* end = value + value_len; value < end; value += 6 )
			{
			// Note, weirdly/unfortunately AddrVal's take
			// addresses in network order but PortVal's
			// take ports in host order.  BitTorrent specifies
			// that both are in network order here.
			uint32_t ad = extract_uint32((u_char*) value);
			uint16_t pt = ntohs((value[4] << 8) | value[5]);

			auto peer = zeek::make_intrusive<zeek::RecordVal>(bittorrent_peer);
			peer->Assign(0, zeek::make_intrusive<zeek::AddrVal>(ad));
			peer->Assign(1, zeek::val_mgr->Port(pt, TRANSPORT_TCP));
			res_val_peers->Assign(std::move(peer), nullptr);
			}
		}
	else
		{
		auto name_ = zeek::make_intrusive<zeek::StringVal>(name_len, name);
		auto benc_value = zeek::make_intrusive<zeek::RecordVal>(bittorrent_benc_value);
		benc_value->Assign(type, zeek::make_intrusive<zeek::StringVal>(value_len, value));
		res_val_benc->Assign(std::move(name_), std::move(benc_value));
		}
	}

void BitTorrentTracker_Analyzer::ResponseBenc(int name_len, char* name,
                                              detail::BTT_BencTypes type, bro_int_t value)
	{
	auto benc_value = zeek::make_intrusive<zeek::RecordVal>(bittorrent_benc_value);
	auto name_ = zeek::make_intrusive<zeek::StringVal>(name_len, name);

	benc_value->Assign(type, zeek::val_mgr->Int(value));
	res_val_benc->Assign(std::move(name_), std::move(benc_value));
	}

void BitTorrentTracker_Analyzer::ResponseBody(void)
	{
	switch ( ResponseParseBenc() ) {
	case 0:
		EmitResponse();
		res_state = detail::BTT_RES_DONE;
		break;

	case -1: // parsing failed
	case -2: // need more data
		break;
	}
	}

int BitTorrentTracker_Analyzer::ResponseParseBenc(void)
	{
#define VIOLATION_IF(expr, msg) \
	{ \
	if ( expr ) \
		{ \
		ProtocolViolation(msg); \
		stop_resp = true; \
		return -1; \
		} \
	}

#define INC_COUNT \
	{ \
	unsigned int count = benc_count.back(); \
	benc_count.pop_back(); \
	benc_count.push_back(count + 1); \
	}

	for ( unsigned int len = res_buf_len - (res_buf_pos - res_buf); len;
	      --len, ++res_buf_pos )
		{
		switch ( benc_state ) {
		case detail::BENC_STATE_EMPTY:
			{
			switch ( res_buf_pos[0] ) {
			case 'd':
				switch ( benc_stack.size() ) {
				case 0: break;
				case 1:
					benc_raw = res_buf_pos;
					benc_raw_type = detail::BENC_TYPE_DIR;
					/* fall through */
				default:
					VIOLATION_IF(benc_stack.back() == 'd' &&
						     ! (benc_count.back() % 2),
						     "BitTorrentTracker: directory key is not a string but a directory")
					++benc_raw_len;
				}

				benc_stack.push_back('d');
				benc_count.push_back(0);
				break;

			case 'l':
				switch ( benc_stack.size() ) {
				case 0:
					VIOLATION_IF(1, "BitTorrentTracker: not a bencoded directory (first char: l)")
					/* fall through */

				case 1:
					benc_raw = res_buf_pos;
					benc_raw_type = detail::BENC_TYPE_LIST;
					/* fall through */

				default:
					VIOLATION_IF(benc_stack.back() == 'd' &&
						     ! (benc_count.back() % 2),
						     "BitTorrentTracker: directory key is not a string but a list")
					++benc_raw_len;
				}

				benc_stack.push_back('l');
				benc_count.push_back(0);
				break;

			case 'i':
				VIOLATION_IF(! benc_stack.size(),
					"BitTorrentTracker: not a bencoded directory (first char: i)")
				VIOLATION_IF(benc_stack.back() == 'd' &&
					     ! (benc_count.back() % 2),
					     "BitTorrentTracker: directory key is not a string but an int")

				if ( benc_raw_type != detail::BENC_TYPE_NONE )
					++benc_raw_len;

				benc_state = detail::BENC_STATE_INT1;
				break;

			case 'e':
				VIOLATION_IF(! benc_stack.size(),
					"BitTorrentTracker: not a bencoded directory (first char: e)")
				VIOLATION_IF(benc_stack.back() == 'd' &&
					     benc_count.back() % 2,
					     "BitTorrentTracker: directory has an odd count of members")

				if ( benc_raw_type != detail::BENC_TYPE_NONE )
					++benc_raw_len;

				if ( benc_stack.size() == 2 )
					{ // coming back to level 1
					ResponseBenc(benc_key_len, benc_key,
							benc_raw_type,
							benc_raw_len, benc_raw);
					benc_key = nullptr;
					benc_key_len = 0;
					benc_raw = nullptr;
					benc_raw_len = 0;
					benc_raw_type = detail::BENC_TYPE_NONE;
					}

				benc_stack.pop_back();
				benc_count.pop_back();

				if ( benc_stack.size() )
					INC_COUNT
				else
					{ // benc parsing successful
					++res_buf_pos;
					return 0;
					}
				break;

			case '0': case '1': case '2': case '3': case '4':
			case '5': case '6': case '7': case '8': case '9':
				VIOLATION_IF(! benc_stack.size(),
					"BitTorrentTracker: not a bencoded directory (first char: [0-9])")

				if ( benc_raw_type != detail::BENC_TYPE_NONE )
					++benc_raw_len;

				benc_strlen = res_buf_pos;
				benc_state = detail::BENC_STATE_STR1;
				break;

			default:
				VIOLATION_IF(1, "BitTorrentTracker: no valid bencoding")
			}
			}
			break;

		case detail::BENC_STATE_INT1:
			benc_int = res_buf_pos;
			if ( res_buf_pos[0] == '-' )
				{
				if ( benc_raw_type != detail::BENC_TYPE_NONE )
					++benc_raw_len;
				benc_state = detail::BENC_STATE_INT2;
				break;
				}

		case detail::BENC_STATE_INT2:
			VIOLATION_IF(res_buf_pos[0] < '0' ||
				     res_buf_pos[0] > '9',
				     "BitTorrentTracker: no valid bencoding")

			if ( benc_raw_type != detail::BENC_TYPE_NONE )
				++benc_raw_len;

			benc_state = detail::BENC_STATE_INT3;
			break;

		case detail::BENC_STATE_INT3:
			if ( res_buf_pos[0] == 'e' )
				{
				if ( sscanf(benc_int, FMT_INT,
					    &benc_int_val) == 1 )
					{
					if ( benc_stack.size() == 1 )
						{
						ResponseBenc(benc_key_len,
							benc_key, detail::BENC_TYPE_INT,
							benc_int_val);
						benc_key = nullptr;
						benc_key_len = 0;
						}
					}
				else
					VIOLATION_IF(1, "BitTorrentTracker: no valid bencoding")

				INC_COUNT
				benc_state = detail::BENC_STATE_EMPTY;
				}

			else
				VIOLATION_IF(res_buf_pos[0] < '0' ||
					     res_buf_pos[0] > '9',
					     "BitTorrentTracker: no valid bencoding");

			if ( benc_raw_type != detail::BENC_TYPE_NONE )
				++benc_raw_len;

			break;

		case detail::BENC_STATE_STR1:
			switch ( res_buf_pos[0] ) {
			case '0': case '1': case '2': case '3': case '4':
			case '5': case '6': case '7': case '8': case '9':
				if ( benc_raw_type != detail::BENC_TYPE_NONE )
					++benc_raw_len;
				break;

			case ':':
				VIOLATION_IF(sscanf(benc_strlen, "%u",
						    &benc_str_len) != 1,
					     "BitTorrentTracker: no valid bencoding")

				benc_str_have = 0;
				benc_str = res_buf_pos + 1;

				if ( benc_stack.size() == 1 &&
				     ! (benc_count.front() % 2) )
					{
					benc_key = benc_str;
					benc_key_len = benc_str_len;
					}

				if ( benc_raw_type != detail::BENC_TYPE_NONE )
					++benc_raw_len;

				benc_state = detail::BENC_STATE_STR2;
				break;

			default:
				VIOLATION_IF(1, "BitTorrentTracker: no valid bencoding")
			}
			break;

		case detail::BENC_STATE_STR2:
			if ( benc_str_have < benc_str_len )
				{
				unsigned int seek =
					std::min(len, benc_str_len - benc_str_have);
				benc_str_have += seek;

				if ( benc_raw_type != detail::BENC_TYPE_NONE )
					benc_raw_len += seek;

				res_buf_pos += seek - 1;
				len -= seek - 1;
				}

			if ( benc_str_have == benc_str_len )
				{
				if ( benc_stack.size() == 1 && benc_key &&
				     benc_key != benc_str )
					{
					ResponseBenc(benc_key_len, benc_key,
							detail::BENC_TYPE_STR,
							benc_str_len, benc_str);
					benc_key_len = 0;
					benc_key = nullptr;
					}

				if ( ! benc_str_len )
					{
					--res_buf_pos;
					++len;
					}

				INC_COUNT
				benc_state = detail::BENC_STATE_EMPTY;
				}
			break;
		}
		}

	return -2;	// need more data
	}

void BitTorrentTracker_Analyzer::EmitResponse(void)
	{
	ProtocolConfirmation();

	if ( bt_tracker_response )
		EnqueueConnEvent(bt_tracker_response,
		                 ConnVal(),
		                 zeek::val_mgr->Count(res_status),
		                 zeek::IntrusivePtr{zeek::AdoptRef{}, res_val_headers},
		                 zeek::IntrusivePtr{zeek::AdoptRef{}, res_val_peers},
		                 zeek::IntrusivePtr{zeek::AdoptRef{}, res_val_benc}
		);

	res_val_headers = nullptr;
	res_val_peers = nullptr;
	res_val_benc = nullptr;
	}

} // namespace zeek::analyzer::bittorrent
