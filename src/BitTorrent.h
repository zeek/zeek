// $Id:$
//
// This code contributed by Nadi Sarrar.

#ifndef bittorrent_h
#define bittorrent_h

#include "TCP.h"

#include "bittorrent_pac.h"

class BitTorrent_Analyzer : public TCP_ApplicationAnalyzer {
public:
	BitTorrent_Analyzer(Connection* conn);
	virtual ~BitTorrent_Analyzer();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(int seq, int len, bool orig);
	virtual void EndpointEOF(TCP_Reassembler* endp);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new BitTorrent_Analyzer(conn); }

	static bool Available()
		{ return bittorrent_peer_handshake || bittorrent_peer_piece; }

protected:
	void DeliverWeird(const char* msg, bool orig);

	binpac::BitTorrent::BitTorrent_Conn* interp;
	bool stop_orig, stop_resp;
	uint64 stream_len_orig, stream_len_resp;
};

#endif
