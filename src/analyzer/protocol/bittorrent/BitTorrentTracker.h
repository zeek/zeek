// This code contributed by Nadi Sarrar.

#pragma once

#include "analyzer/protocol/tcp/TCP.h"

#define BTTRACKER_BUF 2048

ZEEK_FORWARD_DECLARE_NAMESPACED(StringVal, zeek);

namespace zeek::analyzer::bittorrent {

// If the following is defined, then the analyzer will store all of
// the headers seen in tracker messages.
//#define BTTRACKER_STORE_HEADERS 1

namespace detail {

enum BTT_States {
	BTT_REQ_GET,
	BTT_REQ_HEADER,
	BTT_REQ_DONE,

	BTT_RES_STATUS,
	BTT_RES_HEADER,
	BTT_RES_BODY,
	BTT_RES_DONE
};

// "benc" = Bencode ("Bee-Encode"), per http://en.wikipedia.org/wiki/Bencode
enum BTT_BencTypes {
	BENC_TYPE_INT  = 0,
	BENC_TYPE_STR  = 1,
	BENC_TYPE_DIR  = 2,
	BENC_TYPE_LIST = 3,
	BENC_TYPE_NONE = 10
};

enum BTT_BencStates {
	BENC_STATE_EMPTY,
	BENC_STATE_INT1,
	BENC_STATE_INT2,
	BENC_STATE_INT3,
	BENC_STATE_STR1,
	BENC_STATE_STR2,
};

} // namespace detail

class BitTorrentTracker_Analyzer final : public zeek::analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	explicit BitTorrentTracker_Analyzer(zeek::Connection* conn);
	~BitTorrentTracker_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;
	void EndpointEOF(bool is_orig) override;

	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{ return new BitTorrentTracker_Analyzer(conn); }

protected:
	void ClientRequest(int len, const u_char* data);
	void ServerReply(int len, const u_char* data);

	void InitBencParser();

	void DeliverWeird(const char* msg, bool orig);

	bool ParseRequest(char* line);
	void RequestGet(char* uri);
	void RequestHeader(char* name, char* value)
		{ ParseHeader(name, value, true); }
	void EmitRequest();

	bool ParseResponse(char* line);
	void ResponseStatus(char* status);
	void ResponseHeader(char* name, char* value)
		{ ParseHeader(name, value, false); }
	void ResponseBody();
	void ResponseBenc(int name_len, char* name, detail::BTT_BencTypes type,
	                  int value_len, char* value);
	void ResponseBenc(int name_len, char* name, detail::BTT_BencTypes type,
	                  bro_int_t value);
	int ResponseParseBenc();
	void EmitResponse();

	void ParseHeader(char* name, char* value, bool is_request);

	// HTTP state.
	bool keep_alive;

	// Request.
	detail::BTT_States req_state;
	char req_buf[BTTRACKER_BUF];
	char* req_buf_pos;
	unsigned int req_buf_len;
	zeek::StringVal* req_val_uri;
	zeek::TableVal* req_val_headers;

	// Response.
	detail::BTT_States res_state;
	bool res_allow_blank_line;
	char res_buf[BTTRACKER_BUF];
	char* res_buf_pos;
	unsigned int res_buf_len;
	bro_uint_t res_status;
	zeek::TableVal* res_val_headers;
	zeek::TableVal* res_val_peers;
	zeek::TableVal* res_val_benc;

	std::vector<char> benc_stack;
	std::vector<unsigned int> benc_count;
	detail::BTT_BencStates benc_state;

	char* benc_raw;
	detail::BTT_BencTypes benc_raw_type;
	unsigned int benc_raw_len;

	char* benc_key;
	unsigned int benc_key_len;

	char* benc_strlen;
	char* benc_str;
	unsigned int benc_str_len;
	unsigned int benc_str_have;

	char* benc_int;
	bro_int_t benc_int_val;

	// True on protocol violation.
	bool stop_orig, stop_resp;
};

} // namespace zeek::analyzer::bittorrent

namespace analyzer::bittorrent {

	using btt_states [[deprecated("Remove in v4.1. Use zeek::analyzer::bittorrent::detail::BTT_States.")]] = zeek::analyzer::bittorrent::detail::BTT_States;
	constexpr auto BTT_REQ_GET [[deprecated("Remove in v4.1. Use zeek::analyzer::bittorrent::detail::BTT_REQ_GET.")]] = zeek::analyzer::bittorrent::detail::BTT_REQ_GET;
	constexpr auto BTT_REQ_HEADER [[deprecated("Remove in v4.1. Use zeek::analyzer::bittorrent::detail::BTT_REQ_HEADER.")]] = zeek::analyzer::bittorrent::detail::BTT_REQ_HEADER;
	constexpr auto BTT_REQ_DONE [[deprecated("Remove in v4.1. Use zeek::analyzer::bittorrent::detail::BTT_REQ_DONE.")]] = zeek::analyzer::bittorrent::detail::BTT_REQ_DONE;
	constexpr auto BTT_RES_STATUS [[deprecated("Remove in v4.1. Use zeek::analyzer::bittorrent::detail::BTT_RES_STATUS.")]] = zeek::analyzer::bittorrent::detail::BTT_RES_STATUS;
	constexpr auto BTT_RES_HEADER [[deprecated("Remove in v4.1. Use zeek::analyzer::bittorrent::detail::BTT_RES_HEADER.")]] = zeek::analyzer::bittorrent::detail::BTT_RES_HEADER;
	constexpr auto BTT_RES_BODY [[deprecated("Remove in v4.1. Use zeek::analyzer::bittorrent::detail::BTT_RES_BODY.")]] = zeek::analyzer::bittorrent::detail::BTT_RES_BODY;
	constexpr auto BTT_RES_DONE [[deprecated("Remove in v4.1. Use zeek::analyzer::bittorrent::detail::BTT_RES_DONE.")]] = zeek::analyzer::bittorrent::detail::BTT_RES_DONE;

	using btt_benc_types [[deprecated("Remove in v4.1. Use zeek::analyzer::bittorrent::detail::BTT_BencTypes.")]] = zeek::analyzer::bittorrent::detail::BTT_BencTypes;
	constexpr auto BENC_TYPE_INT [[deprecated("Remove in v4.1. Use zeek::analyzer::bittorrent::detail::BENC_TYPE_INT.")]] = zeek::analyzer::bittorrent::detail::BENC_TYPE_INT;
	constexpr auto BENC_TYPE_STR [[deprecated("Remove in v4.1. Use zeek::analyzer::bittorrent::detail::BENC_TYPE_STR.")]] = zeek::analyzer::bittorrent::detail::BENC_TYPE_STR;
	constexpr auto BENC_TYPE_DIR [[deprecated("Remove in v4.1. Use zeek::analyzer::bittorrent::detail::BENC_TYPE_DIR.")]] = zeek::analyzer::bittorrent::detail::BENC_TYPE_DIR;
	constexpr auto BENC_TYPE_LIST [[deprecated("Remove in v4.1. Use zeek::analyzer::bittorrent::detail::BENC_TYPE_LIST.")]] = zeek::analyzer::bittorrent::detail::BENC_TYPE_LIST;
	constexpr auto BENC_TYPE_NONE [[deprecated("Remove in v4.1. Use zeek::analyzer::bittorrent::detail::BENC_TYPE_NONE.")]] = zeek::analyzer::bittorrent::detail::BENC_TYPE_NONE;

	using btt_benc_states [[deprecated("Remove in v4.1. Use zeek::analyzer::bittorrent::detail::BTT_BencStates.")]] = zeek::analyzer::bittorrent::detail::BTT_BencStates;
	constexpr auto BENC_STATE_EMPTY [[deprecated("Remove in v4.1. Use zeek::analyzer::bittorrent::detail::BENC_STATE_EMPTY.")]] = zeek::analyzer::bittorrent::detail::BENC_STATE_EMPTY;
	constexpr auto BENC_STATE_INT1 [[deprecated("Remove in v4.1. Use zeek::analyzer::bittorrent::detail::BENC_STATE_INT1.")]] = zeek::analyzer::bittorrent::detail::BENC_STATE_INT1;
	constexpr auto BENC_STATE_INT2 [[deprecated("Remove in v4.1. Use zeek::analyzer::bittorrent::detail::BENC_STATE_INT2.")]] = zeek::analyzer::bittorrent::detail::BENC_STATE_INT2;
	constexpr auto BENC_STATE_INT3 [[deprecated("Remove in v4.1. Use zeek::analyzer::bittorrent::detail::BENC_STATE_INT3.")]] = zeek::analyzer::bittorrent::detail::BENC_STATE_INT3;
	constexpr auto BENC_STATE_STR1 [[deprecated("Remove in v4.1. Use zeek::analyzer::bittorrent::detail::BENC_STATE_STR1.")]] = zeek::analyzer::bittorrent::detail::BENC_STATE_STR1;
	constexpr auto BENC_STATE_STR2 [[deprecated("Remove in v4.1. Use zeek::analyzer::bittorrent::detail::BENC_STATE_STR2.")]] = zeek::analyzer::bittorrent::detail::BENC_STATE_STR2;

	using BitTorrentTracker_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::bittorrent::BitTorrentTracker_Analyzer.")]] = zeek::analyzer::bittorrent::BitTorrentTracker_Analyzer;

	}
