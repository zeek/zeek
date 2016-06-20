#ifndef ANALYZER_PROTOCOL_SMB_SMB_H
#define ANALYZER_PROTOCOL_SMB_SMB_H

// SMB (CIFS) analyzer.
// Reference: http://www.snia.org/tech_activities/CIFS/CIFS-TR-1p00_FINAL.pdf

#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/rpc/RPC.h"
#include "smb_pac.h"

namespace analyzer { namespace smb {

class Contents_SMB : public tcp::TCP_SupportAnalyzer {
public:
	Contents_SMB(Connection* conn, bool orig);
	~Contents_SMB();

	void DeliverStream(int len, const u_char* data, bool orig) override;

protected:
	typedef enum {
		WAIT_FOR_HDR,
		WAIT_FOR_DATA
	} state_t;
	typedef enum {
		NEED_RESYNC,
		INSYNC,
	} resync_state_t;
	void Init() override;
	virtual bool CheckResync(int& len, const u_char*& data, bool orig);
	void Undelivered(uint64 seq, int len, bool orig) override;
	virtual void NeedResync() {
		resync_state = NEED_RESYNC;
		state = WAIT_FOR_HDR;
	}

	bool HasSMBHeader(int len, const u_char* data);

	void DeliverSMB(int len, const u_char* data);

	rpc::RPC_Reasm_Buffer hdr_buf; // Reassembles the NetBIOS length and glue.
	rpc::RPC_Reasm_Buffer msg_buf; // Reassembles the SMB message.
	int msg_len;
	int msg_type;
	double first_time;   // timestamp of first packet of current message
	double last_time;    // timestamp of last pakcet of current message
	state_t state;
	resync_state_t resync_state;
};

class SMB_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	SMB_Analyzer(Connection* conn);
	virtual ~SMB_Analyzer();

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64 seq, int len, bool orig) override;
	void EndpointEOF(bool is_orig) override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new SMB_Analyzer(conn); }

protected:
	binpac::SMB::SMB_Conn* interp;

	// Count the number of chunks received by the analyzer
	// but only used to count the first few.
	uint8 chunks;
};

} } // namespace analyzer::*

#endif
