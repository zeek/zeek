// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <list>

#include "zeek/analyzer/protocol/mime/MIME.h"
#include "zeek/analyzer/protocol/tcp/ContentLine.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

#undef SMTP_CMD_DEF
#define SMTP_CMD_DEF(cmd) SMTP_CMD_##cmd,

namespace zeek::analyzer::smtp
	{
namespace detail
	{

enum SMTP_Cmd
	{
#include "SMTP_cmd.def"
	};

// State is updated on every SMTP reply.
enum SMTP_State
	{
	SMTP_CONNECTED, // 0: before the opening message
	SMTP_INITIATED, // 1: after opening message 220, EHLO/HELO expected
	SMTP_NOT_AVAILABLE, // 2: after opening message 554, etc.
	SMTP_READY, // 3: after EHLO/HELO and reply 250
	SMTP_MAIL_OK, // 4: after MAIL/SEND/SOML/SAML and 250, RCPT expected
	SMTP_RCPT_OK, // 5: after one successful RCPT, DATA or more RCPT expected
	SMTP_IN_DATA, // 6: after DATA
	SMTP_AFTER_DATA, // 7: after . and before reply
	SMTP_IN_AUTH, // 8: after AUTH and 334
	SMTP_IN_TLS, // 9: after STARTTLS/X-ANONYMOUSTLS and 220
	SMTP_QUIT, // 10: after QUIT
	SMTP_AFTER_GAP, // 11: after a gap is detected
	SMTP_GAP_RECOVERY, // 12: after the first reply after a gap
	};

	} // namespace detail

class SMTP_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer
	{
public:
	explicit SMTP_Analyzer(Connection* conn);
	~SMTP_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void ConnectionFinished(bool half_finished) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;

	void SkipData() { skip_data = 1; } // skip delivery of data lines

	static analyzer::Analyzer* Instantiate(Connection* conn) { return new SMTP_Analyzer(conn); }

protected:
	void ProcessLine(int length, const char* line, bool orig);
	void NewCmd(int cmd_code);
	void NewReply(int reply_code, bool orig);
	void ProcessExtension(int ext_len, const char* ext);
	void ProcessData(int length, const char* line);

	void UpdateState(int cmd_code, int reply_code, bool orig);

	void BeginData(bool orig);
	void EndData();

	int ParseCmd(int cmd_len, const char* cmd);

	void RequestEvent(int cmd_len, const char* cmd, int arg_len, const char* arg);
	void Unexpected(bool is_sender, const char* msg, int detail_len, const char* detail);
	void UnexpectedCommand(int cmd_code, int reply_code);
	void UnexpectedReply(int cmd_code, int reply_code);
	void StartTLS();

	bool orig_is_sender;
	bool expect_sender, expect_recover;
	bool pipelining; // whether pipelining is supported
	int state;
	int last_replied_cmd;
	int first_cmd; // first un-replied SMTP cmd, or -1
	int pending_reply; // code assoc. w/ multi-line reply, or 0
	std::list<int> pending_cmd_q; // to support pipelining
	bool skip_data; // whether to skip message body
	String* line_after_gap; // last line before the first reply
	                        // after a gap

	analyzer::mime::MIME_Mail* mail;

private:
	analyzer::tcp::ContentLine_Analyzer* cl_orig;
	analyzer::tcp::ContentLine_Analyzer* cl_resp;
	};

	} // namespace zeek::analyzer::smtp
