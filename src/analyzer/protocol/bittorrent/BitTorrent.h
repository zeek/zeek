// This code contributed by Nadi Sarrar.

#pragma once

#include "zeek/analyzer/protocol/tcp/TCP.h"

#include "analyzer/protocol/bittorrent/bittorrent_pac.h"

namespace zeek::analyzer::bittorrent {

class BitTorrent_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	explicit BitTorrent_Analyzer(Connection* conn);
	~BitTorrent_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;
	void EndpointEOF(bool is_orig) override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new BitTorrent_Analyzer(conn); }

protected:
	void DeliverWeird(const char* msg, bool orig);

	binpac::BitTorrent::BitTorrent_Conn* interp;
	bool stop_orig, stop_resp;
	uint64_t stream_len_orig, stream_len_resp;
};

} // namespace zeek::analyzer::bittorrent
