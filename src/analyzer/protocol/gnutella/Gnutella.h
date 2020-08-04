// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::gnutella {

constexpr int ORIG_OK = 0x1;
constexpr int RESP_OK = 0x2;

constexpr int GNUTELLA_MSG_SIZE = 23;
constexpr int GNUTELLA_MAX_PAYLOAD = 1024;

namespace detail {

class GnutellaMsgState {
public:
	GnutellaMsgState ();

	std::string buffer;
	int current_offset;
	int got_CR;
	std::string headers;
	char msg[GNUTELLA_MSG_SIZE];
	u_char msg_hops;
	unsigned int msg_len;
	int msg_pos;
	int msg_sent;
	u_char msg_type;
	u_char msg_ttl;
	char payload[GNUTELLA_MAX_PAYLOAD];
	unsigned int payload_len;
	unsigned int payload_left;
};

} // namespace detail

class Gnutella_Analyzer : public zeek::analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	explicit Gnutella_Analyzer(zeek::Connection* conn);
	~Gnutella_Analyzer() override;

	void Done () override;
	void DeliverStream(int len, const u_char* data, bool orig) override;

	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{ return new Gnutella_Analyzer(conn); }

private:
	bool NextLine(const u_char* data, int len);

	bool GnutellaOK(std::string header);
	bool IsHTTP(std::string header);

	bool Established() const	{ return state == (ORIG_OK | RESP_OK); }

	void DeliverLines(int len, const u_char* data, bool orig);

	void SendEvents(detail::GnutellaMsgState* p, bool is_orig);

	void DissectMessage(char* msg);
	void DeliverMessages(int len, const u_char* data, bool orig);

	int state;
	int new_state;
	int sent_establish;

	detail::GnutellaMsgState* orig_msg_state;
	detail::GnutellaMsgState* resp_msg_state;
	detail::GnutellaMsgState* ms;
};

} // namespace zeek::analyzer::gnutella

namespace analyzer::gnutella {

	using GnutellaMsgState [[deprecated("Remove in v4.1. Use zeek::analyzer::gnutella::detail::GnutellaMsgState.")]] = zeek::analyzer::gnutella::detail::GnutellaMsgState;
	using Gnutella_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::gnutella::Gnutella_Analyzer.")]] = zeek::analyzer::gnutella::Gnutella_Analyzer;

} // namespace analyzer::gnutella
