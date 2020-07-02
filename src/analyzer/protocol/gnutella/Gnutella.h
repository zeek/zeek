// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "analyzer/protocol/tcp/TCP.h"

#define ORIG_OK               0x1
#define RESP_OK               0x2

#define GNUTELLA_MSG_SIZE     23
#define GNUTELLA_MAX_PAYLOAD  1024

namespace analyzer { namespace gnutella {

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


class Gnutella_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	explicit Gnutella_Analyzer(Connection* conn);
	~Gnutella_Analyzer() override;

	void Done () override;
	void DeliverStream(int len, const u_char* data, bool orig) override;

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new Gnutella_Analyzer(conn); }

private:
	bool NextLine(const u_char* data, int len);

	bool GnutellaOK(std::string header);
	bool IsHTTP(std::string header);

	bool Established() const	{ return state == (ORIG_OK | RESP_OK); }

	void DeliverLines(int len, const u_char* data, bool orig);

	void SendEvents(GnutellaMsgState* p, bool is_orig);

	void DissectMessage(char* msg);
	void DeliverMessages(int len, const u_char* data, bool orig);

	int state;
	int new_state;
	int sent_establish;

	GnutellaMsgState* orig_msg_state;
	GnutellaMsgState* resp_msg_state;
	GnutellaMsgState* ms;
};

} } // namespace analyzer::*
