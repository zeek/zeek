#ifndef ANALYZER_PROTOCOL_SMB_SMB_H
#define ANALYZER_PROTOCOL_SMB_SMB_H

#include "analyzer/protocol/tcp/TCP.h"
#include "smb_pac.h"

namespace analyzer { namespace smb {

class SMB_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	explicit SMB_Analyzer(Connection* conn);
	~SMB_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64 seq, int len, bool orig) override;
	void EndpointEOF(bool is_orig) override;

	bool HasSMBHeader(int len, const u_char* data);
	void NeedResync();

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new SMB_Analyzer(conn); }

protected:
	binpac::SMB::SMB_Conn* interp;

	// Count the number of chunks received by the analyzer
	// but only used to count the first few.
	uint8 chunks;

	bool need_sync;
};

} } // namespace analyzer::*

#endif
