// See the file "COPYING" in the main distribution directory for copyright.

#ifndef gnutella_h
#define gnutella_h

#include "TCP.h"

#define ORIG_OK               0x1
#define RESP_OK               0x2

#define GNUTELLA_MSG_SIZE     23
#define GNUTELLA_MAX_PAYLOAD  1024

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


class Gnutella_Analyzer : public TCP_ApplicationAnalyzer {
public:
	Gnutella_Analyzer(Connection* conn);
	~Gnutella_Analyzer();

	virtual void Done ();
	virtual void DeliverStream(int len, const u_char* data, bool orig);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new Gnutella_Analyzer(conn); }

	static bool Available()
		{
		return gnutella_text_msg || gnutella_binary_msg ||
			gnutella_partial_binary_msg || gnutella_establish ||
			gnutella_not_establish || gnutella_http_notify;
		}

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

#endif
