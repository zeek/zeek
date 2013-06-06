// This code contributed by Nadi Sarrar.

#ifndef ANALYZER_PROTOCOL_BITTORRENT_BITTORRENT_H
#define ANALYZER_PROTOCOL_BITTORRENT_BITTORRENT_H

#include "analyzer/protocol/tcp/TCP.h"

#include "bittorrent_pac.h"

namespace analyzer { namespace bittorrent {

class BitTorrent_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	BitTorrent_Analyzer(Connection* conn);
	virtual ~BitTorrent_Analyzer();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(int seq, int len, bool orig);
	virtual void EndpointEOF(bool is_orig);

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new BitTorrent_Analyzer(conn); }

protected:
	void DeliverWeird(const char* msg, bool orig);

	binpac::BitTorrent::BitTorrent_Conn* interp;
	bool stop_orig, stop_resp;
	uint64 stream_len_orig, stream_len_resp;
};

} } // namespace analyzer::* 

#endif
