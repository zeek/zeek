// This code contributed by Nadi Sarrar.

#pragma once

#include "analyzer/protocol/tcp/TCP.h"

#include "bittorrent_pac.h"

namespace analyzer { namespace bittorrent {

class BitTorrent_Analyzer final : public tcp::TCP_ApplicationAnalyzer {
public:
	explicit BitTorrent_Analyzer(Connection* conn);
	~BitTorrent_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;
	void EndpointEOF(bool is_orig) override;

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new BitTorrent_Analyzer(conn); }

protected:
	void DeliverWeird(const char* msg, bool orig);

	binpac::BitTorrent::BitTorrent_Conn* interp;
	bool stop_orig, stop_resp;
	uint64_t stream_len_orig, stream_len_resp;
};

} } // namespace analyzer::*
