#pragma once

#include "zeek/analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/smb/smb_pac.h"

namespace zeek::analyzer::smb {

class SMB_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	explicit SMB_Analyzer(Connection* conn);
	~SMB_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;
	void EndpointEOF(bool is_orig) override;

	bool HasSMBHeader(int len, const u_char* data);
	void NeedResync();

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new SMB_Analyzer(conn); }

protected:
	binpac::SMB::SMB_Conn* interp;

	// Count the number of chunks received by the analyzer
	// but only used to count the first few.
	uint8_t chunks;

	bool need_sync;
};

} // namespace zeek::analyzer::smb
