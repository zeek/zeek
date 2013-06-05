// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_SMB_SMB_H
#define ANALYZER_PROTOCOL_SMB_SMB_H

// SMB (CIFS) analyzer.
// Reference: http://www.snia.org/tech_activities/CIFS/CIFS-TR-1p00_FINAL.pdf

#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/dce-rpc/DCE_RPC.h"
#include "smb_pac.h"

namespace analyzer { namespace smb {

enum IPC_named_pipe {
	IPC_NONE,
	IPC_LOCATOR,
	IPC_EPMAPPER,
	IPC_SAMR,	// Security Account Manager
};

class SMB_Body : public binpac::SMB::SMB_body {
public:
	SMB_Body(const u_char* data, const u_char* data_end)
		: binpac::SMB::SMB_body()
		{
		data_ = data;
		Parse(data, data_end);
		data_length_ = body_length();
		if ( data + data_length_ > data_end )
			data_length_ = data_end - data;
		}

	const u_char* data() const	{ return data_; }
	int length() const 		{ return data_length_; }

protected:
	const u_char* data_;
	int data_length_;
};

class SMB_Session {
public:
	SMB_Session(analyzer::Analyzer* analyzer);
	~SMB_Session();

	void Deliver(int is_orig, int len, const u_char* msg);

protected:
	void ParseMessage(int is_orig, int cmd,
				binpac::SMB::SMB_header const &hdr,
				SMB_Body const &body);

	int ParseNegotiate(binpac::SMB::SMB_header const &hdr,
				SMB_Body const &body);

	int ParseNegotiateResponse(binpac::SMB::SMB_header const &hdr,
				SMB_Body const &body);

	int ParseAndx(int is_orig, binpac::SMB::SMB_header const &hdr,
				SMB_Body const &body);

	int ParseClose(int is_orig, binpac::SMB::SMB_header const &hdr,
				SMB_Body const &body);

	int ParseLogoffAndx(int is_orig, binpac::SMB::SMB_header const &hdr,
				SMB_Body const &body);

	int ParseSetupAndx(int is_orig, binpac::SMB::SMB_header const &hdr,
				SMB_Body const &body);

	int ParseTreeConnectAndx(binpac::SMB::SMB_header const &hdr,
				SMB_Body const &body);

	int ParseTreeDisconnect(int is_orig, binpac::SMB::SMB_header const &hdr,
				SMB_Body const &body);

	int ParseNtCreateAndx(binpac::SMB::SMB_header const &hdr,
				SMB_Body const &body);

	int ParseReadAndx(binpac::SMB::SMB_header const &hdr,
				SMB_Body const &body);

	int ParseReadAndxResponse(binpac::SMB::SMB_header const &hdr,
				SMB_Body const &body);

	int ParseWriteAndx(binpac::SMB::SMB_header const &hdr,
				SMB_Body const &body);

	int ParseWriteAndxResponse(binpac::SMB::SMB_header const &hdr,
				SMB_Body const &body);

	int ParseTransaction(int is_orig, int cmd,
				binpac::SMB::SMB_header const &hdr,
				SMB_Body const &body);

	int TransactionEvent(EventHandlerPtr f, int is_orig,
				binpac::SMB::SMB_header const &hdr,
				binpac::SMB::SMB_transaction const &trans,
				int data_count,
				binpac::SMB::SMB_transaction_data* data);

	int TransactionEvent(EventHandlerPtr f, int is_orig,
				binpac::SMB::SMB_header const &hdr,
				binpac::SMB::SMB_transaction_secondary const &trans,
				int data_count,
				binpac::SMB::SMB_transaction_data* data);

	int TransactionEvent(EventHandlerPtr f, int is_orig,
				binpac::SMB::SMB_header const &hdr,
				binpac::SMB::SMB_transaction_response const &trans,
				int data_count,
				binpac::SMB::SMB_transaction_data* data);

	int ParseTransactionRequest(int cmd,
				binpac::SMB::SMB_header const &hdr,
				SMB_Body const &body);

	int ParseTransactionSecondaryRequest(int cmd,
				binpac::SMB::SMB_header const &hdr,
				SMB_Body const &body);

	int ParseTransactionResponse(int cmd,
				binpac::SMB::SMB_header const &hdr,
				SMB_Body const &body);

	int ParseGetDFSReferral(binpac::SMB::SMB_header const &hdr,
				int param_count, const u_char* param);

	BroString* ExtractString(binpac::SMB::SMB_string const* s);
	BroString* ExtractString(binpac::SMB::SMB_ascii_string const* s);
	BroString* ExtractString(binpac::SMB::SMB_unicode_string const* s);

	bool LooksLikeRPC(int len, const u_char* msg);
	bool CheckRPC(int is_orig, int len, const u_char* msg);

	int AndxOffset(int is_orig, int &next_command) const;

	void Weird(const char* msg);

	const binpac::SMB::SMB_andx* const andx(int is_orig) const
		{
		return is_orig ? andx_[1] : andx_[0];
		}

	void set_andx(int is_orig, binpac::SMB::SMB_andx* andx);
	 
	Val* BuildHeaderVal(binpac::SMB::SMB_header const &hdr);
	Val* BuildTransactionVal(binpac::SMB::SMB_transaction const &trans);
	Val* BuildTransactionVal(binpac::SMB::SMB_transaction_secondary const &trans);
	Val* BuildTransactionVal(binpac::SMB::SMB_transaction_response const &trans);
	Val* BuildTransactionDataVal(binpac::SMB::SMB_transaction_data* data);

	analyzer::Analyzer* analyzer;
	dce_rpc::DCE_RPC_Session* dce_rpc_session;
	enum IPC_named_pipe IPC_pipe;
	int is_IPC;
	int req_cmd;
	uint16 transaction_subcmd;
	bool smb_mailslot_prot;
	bool smb_pipe_prot;
	StringVal* transaction_name;
	binpac::SMB::SMB_andx* andx_[2];
};

class Contents_SMB : public tcp::TCP_SupportAnalyzer {
public:
	Contents_SMB(Connection* conn, bool orig, SMB_Session* smb_session);
	~Contents_SMB();

	virtual void DeliverStream(int len, const u_char* data, bool orig);

protected:
	void InitMsgBuf();

	void DeliverSMB(int len, const u_char* data);

	SMB_Session* smb_session;
	u_char dshdr[4];
	u_char* msg_buf;
	int msg_len;
	int buf_n;	// number of bytes in msg_buf
	int buf_len;	// size off msg_buf
};

class SMB_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	SMB_Analyzer(Connection* conn);
	~SMB_Analyzer();

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new SMB_Analyzer(conn); }

protected:
	SMB_Session* smb_session;
	Contents_SMB* o_smb;
	Contents_SMB* r_smb;
};

} } // namespace analyzer::* 

#endif
