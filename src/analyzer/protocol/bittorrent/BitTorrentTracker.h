// This code contributed by Nadi Sarrar.

#ifndef ANALYZER_PROTOCOL_BITTORRENT_BITTORRENTTRACKER_H
#define ANALYZER_PROTOCOL_BITTORRENT_BITTORRENTTRACKER_H

#include "analyzer/protocol/tcp/TCP.h"

#define BTTRACKER_BUF 2048

namespace analyzer { namespace bittorrent {

// If the following is defined, then the analyzer will store all of
// the headers seen in tracker messages.
//#define BTTRACKER_STORE_HEADERS 1

enum btt_states {
	BTT_REQ_GET,
	BTT_REQ_HEADER,
	BTT_REQ_DONE,

	BTT_RES_STATUS,
	BTT_RES_HEADER,
	BTT_RES_BODY,
	BTT_RES_DONE,
};

// "benc" = Bencode ("Bee-Encode"), per http://en.wikipedia.org/wiki/Bencode
enum btt_benc_types {
	BENC_TYPE_INT  = 0,
	BENC_TYPE_STR  = 1,
	BENC_TYPE_DIR  = 2,
	BENC_TYPE_LIST = 3,
	BENC_TYPE_NONE = 10,
};

enum btt_benc_states {
	BENC_STATE_EMPTY,
	BENC_STATE_INT1,
	BENC_STATE_INT2,
	BENC_STATE_INT3,
	BENC_STATE_STR1,
	BENC_STATE_STR2,
};

class BitTorrentTracker_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	BitTorrentTracker_Analyzer(Connection* conn);
	virtual ~BitTorrentTracker_Analyzer();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(int seq, int len, bool orig);
	virtual void EndpointEOF(bool is_orig);

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new BitTorrentTracker_Analyzer(conn); }

protected:
	void ClientRequest(int len, const u_char* data);
	void ServerReply(int len, const u_char* data);

	void InitBencParser(void);

	void DeliverWeird(const char* msg, bool orig);

	bool ParseRequest(char* line);
	void RequestGet(char* uri);
	void RequestHeader(char* name, char* value)
		{ ParseHeader(name, value, true); }
	void EmitRequest(void);

	bool ParseResponse(char* line);
	void ResponseStatus(char* status);
	void ResponseHeader(char* name, char* value)
		{ ParseHeader(name, value, false); }
	void ResponseBody(void);
	void ResponseBenc(int name_len, char* name, enum btt_benc_types type,
				int value_len, char* value);
	void ResponseBenc(int name_len, char* name, enum btt_benc_types type,
				bro_int_t value);
	int ResponseParseBenc(void);
	void EmitResponse(void);

	void ParseHeader(char* name, char* value, bool is_request);

	// HTTP state.
	bool keep_alive;

	// Request.
	enum btt_states req_state;
	char req_buf[BTTRACKER_BUF];
	char* req_buf_pos;
	unsigned int req_buf_len;
	StringVal* req_val_uri;
	TableVal* req_val_headers;

	// Response.
	enum btt_states res_state;
	bool res_allow_blank_line;
	char res_buf[BTTRACKER_BUF];
	char* res_buf_pos;
	unsigned int res_buf_len;
	bro_uint_t res_status;
	TableVal* res_val_headers;
	TableVal* res_val_peers;
	TableVal* res_val_benc;

	vector<char> benc_stack;
	vector<unsigned int> benc_count;
	enum btt_benc_states benc_state;

	char* benc_raw;
	enum btt_benc_types benc_raw_type;
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

} } // namespace analyzer::* 

#endif
