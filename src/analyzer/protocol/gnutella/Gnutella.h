// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_GNUTELLA_GNUTELLA_H
#define ANALYZER_PROTOCOL_GNUTELLA_GNUTELLA_H

#include "analyzer/protocol/tcp/TCP.h"

#define ORIG_OK               0x1
#define RESP_OK               0x2

#define GNUTELLA_MSG_SIZE     23
#define GNUTELLA_MAX_PAYLOAD  1024

namespace analyzer { namespace gnutella {

class GnutellaMsgState {
public:
	GnutellaMsgState ();

	string buffer;
	int current_offset;
	int got_CR;
	string headers;
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
	Gnutella_Analyzer(Connection* conn);
	~Gnutella_Analyzer();

	virtual void Done ();
	virtual void DeliverStream(int len, const u_char* data, bool orig);

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new Gnutella_Analyzer(conn); }

private:
	int NextLine(const u_char* data, int len);

	int GnutellaOK(string header);
	int IsHTTP(string header);

	int Established() const	{ return state == (ORIG_OK | RESP_OK); }

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

#endif
