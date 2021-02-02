// This code contributed by Nadi Sarrar.

#pragma once

#include "zeek/analyzer/protocol/tcp/TCP.h"

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

class BitTorrentTracker_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	explicit BitTorrentTracker_Analyzer(Connection* conn);
	~BitTorrentTracker_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;
	void EndpointEOF(bool is_orig) override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
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
	StringVal* req_val_uri;
	TableVal* req_val_headers;

	// Response.
	detail::BTT_States res_state;
	bool res_allow_blank_line;
	char res_buf[BTTRACKER_BUF];
	char* res_buf_pos;
	unsigned int res_buf_len;
	bro_uint_t res_status;
	TableVal* res_val_headers;
	TableVal* res_val_peers;
	TableVal* res_val_benc;

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
