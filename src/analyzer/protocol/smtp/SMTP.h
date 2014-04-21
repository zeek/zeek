// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_SMTP_SMTP_H
#define ANALYZER_PROTOCOL_SMTP_SMTP_H

#include <list>
using namespace std;

#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/mime/MIME.h"

#undef SMTP_CMD_DEF
#define SMTP_CMD_DEF(cmd)	SMTP_CMD_##cmd,

namespace analyzer { namespace smtp {

typedef enum {
#include "SMTP_cmd.def"
} SMTP_Cmd;

// State is updated on every SMTP reply.
typedef enum {
	SMTP_CONNECTED,		// 0: before the opening message
	SMTP_INITIATED,		// 1: after opening message 220, EHLO/HELO expected
	SMTP_NOT_AVAILABLE,	// 2: after opening message 554, etc.
	SMTP_READY,		// 3: after EHLO/HELO and reply 250
	SMTP_MAIL_OK,		// 4: after MAIL/SEND/SOML/SAML and 250, RCPT expected
	SMTP_RCPT_OK,		// 5: after one successful RCPT, DATA or more RCPT expected
	SMTP_IN_DATA,		// 6: after DATA
	SMTP_AFTER_DATA,	// 7: after . and before reply
	SMTP_IN_AUTH,		// 8: after AUTH and 334
	SMTP_IN_TLS,		// 9: after STARTTLS and 220
	SMTP_QUIT,		// 10: after QUIT
	SMTP_AFTER_GAP,		// 11: after a gap is detected
	SMTP_GAP_RECOVERY,	// 12: after the first reply after a gap
} SMTP_State;


class SMTP_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	SMTP_Analyzer(Connection* conn);
	~SMTP_Analyzer();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void ConnectionFinished(int half_finished);
	virtual void Undelivered(int seq, int len, bool orig);

	void SkipData()	{ skip_data = 1; }	// skip delivery of data lines

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{
		return new SMTP_Analyzer(conn);
		}

protected:

	void ProcessLine(int length, const char* line, bool orig);
	void NewCmd(const int cmd_code);
	void NewReply(const int reply_code);
	void ProcessExtension(int ext_len, const char* ext);
	void ProcessData(int length, const char* line);

	void UpdateState(const int cmd_code, const int reply_code);

	void BeginData();
	void EndData();

	int ParseCmd(int cmd_len, const char* cmd);

	void RequestEvent(int cmd_len, const char* cmd,
				int arg_len, const char* arg);
	void Unexpected(const int is_orig, const char* msg,
				int detail_len, const char* detail);
	void UnexpectedCommand(const int cmd_code, const int reply_code);
	void UnexpectedReply(const int cmd_code, const int reply_code);

	bool orig_is_sender;
	int expect_sender, expect_recver;
	int state;
	int last_replied_cmd;
	int first_cmd;			// first un-replied SMTP cmd, or -1
	int pending_reply;		// code assoc. w/ multi-line reply, or 0
	int pipelining;			// whether pipelining is supported
	list<int> pending_cmd_q;	// to support pipelining
	int skip_data;			// whether to skip message body
	BroString* line_after_gap;	// last line before the first reply
					// after a gap

	mime::MIME_Mail* mail;
};

} } // namespace analyzer::* 

#endif
