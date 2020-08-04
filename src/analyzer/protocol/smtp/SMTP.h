// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <list>

#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/tcp/ContentLine.h"
#include "analyzer/protocol/mime/MIME.h"

#undef SMTP_CMD_DEF
#define SMTP_CMD_DEF(cmd)	SMTP_CMD_##cmd,

namespace zeek::analyzer::smtp {
namespace detail {

enum SMTP_Cmd {
#include "SMTP_cmd.def"
};

// State is updated on every SMTP reply.
enum SMTP_State {
	SMTP_CONNECTED,		// 0: before the opening message
	SMTP_INITIATED,		// 1: after opening message 220, EHLO/HELO expected
	SMTP_NOT_AVAILABLE,	// 2: after opening message 554, etc.
	SMTP_READY,		// 3: after EHLO/HELO and reply 250
	SMTP_MAIL_OK,		// 4: after MAIL/SEND/SOML/SAML and 250, RCPT expected
	SMTP_RCPT_OK,		// 5: after one successful RCPT, DATA or more RCPT expected
	SMTP_IN_DATA,		// 6: after DATA
	SMTP_AFTER_DATA,	// 7: after . and before reply
	SMTP_IN_AUTH,		// 8: after AUTH and 334
	SMTP_IN_TLS,		// 9: after STARTTLS/X-ANONYMOUSTLS and 220
	SMTP_QUIT,		// 10: after QUIT
	SMTP_AFTER_GAP,		// 11: after a gap is detected
	SMTP_GAP_RECOVERY,	// 12: after the first reply after a gap
};

} // namespace detail

class SMTP_Analyzer final : public zeek::analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	explicit SMTP_Analyzer(zeek::Connection* conn);
	~SMTP_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void ConnectionFinished(bool half_finished) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;

	void SkipData()	{ skip_data = 1; }	// skip delivery of data lines

	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{
		return new SMTP_Analyzer(conn);
		}

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

	void RequestEvent(int cmd_len, const char* cmd,
				int arg_len, const char* arg);
	void Unexpected(bool is_sender, const char* msg,
				int detail_len, const char* detail);
	void UnexpectedCommand(int cmd_code, int reply_code);
	void UnexpectedReply(int cmd_code, int reply_code);
	void StartTLS();

	bool orig_is_sender;
	bool expect_sender, expect_recver;
	bool pipelining;			// whether pipelining is supported
	int state;
	int last_replied_cmd;
	int first_cmd;			// first un-replied SMTP cmd, or -1
	int pending_reply;		// code assoc. w/ multi-line reply, or 0
	std::list<int> pending_cmd_q;	// to support pipelining
	bool skip_data;			// whether to skip message body
	zeek::String* line_after_gap;	// last line before the first reply
					// after a gap

	zeek::analyzer::mime::MIME_Mail* mail;

private:
	zeek::analyzer::tcp::ContentLine_Analyzer* cl_orig;
	zeek::analyzer::tcp::ContentLine_Analyzer* cl_resp;
};

} // namespace zeek::analyzer::smtp

namespace analyzer::smtp {

using SMTP_Cmd [[deprecated("Remove in v4.1. Use zeek::analyzer::smtp::detail::SMTP_Cmd.")]] = zeek::analyzer::smtp::detail::SMTP_Cmd;
// The values from SMTP_Cmd come from a #include
using SMTP_State [[deprecated("Remove in v4.1. Use zeek::analyzer::smtp::detail::SMTP_State.")]] = zeek::analyzer::smtp::detail::SMTP_State;
constexpr auto SMTP_CONNECTED [[deprecated("Remove in v4.1. Uze zeek::analyzer::smtp::detail::SMTP_CONNECTED.")]] = zeek::analyzer::smtp::detail::SMTP_CONNECTED;
constexpr auto SMTP_INITIATED [[deprecated("Remove in v4.1. Uze zeek::analyzer::smtp::detail::SMTP_INITIATED.")]] = zeek::analyzer::smtp::detail::SMTP_INITIATED;
constexpr auto SMTP_NOT_AVAILABLE [[deprecated("Remove in v4.1. Uze zeek::analyzer::smtp::detail::SMTP_NOT_AVAILABLE.")]] = zeek::analyzer::smtp::detail::SMTP_NOT_AVAILABLE;
constexpr auto SMTP_READY [[deprecated("Remove in v4.1. Uze zeek::analyzer::smtp::detail::SMTP_READY.")]] = zeek::analyzer::smtp::detail::SMTP_READY;
constexpr auto SMTP_MAIL_OK [[deprecated("Remove in v4.1. Uze zeek::analyzer::smtp::detail::SMTP_MAIL_OK.")]] = zeek::analyzer::smtp::detail::SMTP_MAIL_OK;
constexpr auto SMTP_RCPT_OK [[deprecated("Remove in v4.1. Uze zeek::analyzer::smtp::detail::SMTP_RCPT_OK.")]] = zeek::analyzer::smtp::detail::SMTP_RCPT_OK;
constexpr auto SMTP_IN_DATA [[deprecated("Remove in v4.1. Uze zeek::analyzer::smtp::detail::SMTP_IN_DATA.")]] = zeek::analyzer::smtp::detail::SMTP_IN_DATA;
constexpr auto SMTP_AFTER_DATA [[deprecated("Remove in v4.1. Uze zeek::analyzer::smtp::detail::SMTP_AFTER_DATA.")]] = zeek::analyzer::smtp::detail::SMTP_AFTER_DATA;
constexpr auto SMTP_IN_AUTH [[deprecated("Remove in v4.1. Uze zeek::analyzer::smtp::detail::SMTP_IN_AUTH.")]] = zeek::analyzer::smtp::detail::SMTP_IN_AUTH;
constexpr auto SMTP_IN_TLS [[deprecated("Remove in v4.1. Uze zeek::analyzer::smtp::detail::SMTP_IN_TLS.")]] = zeek::analyzer::smtp::detail::SMTP_IN_TLS;
constexpr auto SMTP_QUIT [[deprecated("Remove in v4.1. Uze zeek::analyzer::smtp::detail::SMTP_QUIT.")]] = zeek::analyzer::smtp::detail::SMTP_QUIT;
constexpr auto SMTP_AFTER_GAP [[deprecated("Remove in v4.1. Uze zeek::analyzer::smtp::detail::SMTP_AFTER_GAP.")]] = zeek::analyzer::smtp::detail::SMTP_AFTER_GAP;
constexpr auto SMTP_GAP_RECOVERY [[deprecated("Remove in v4.1. Uze zeek::analyzer::smtp::detail::SMTP_GAP_RECOVERY.")]] = zeek::analyzer::smtp::detail::SMTP_GAP_RECOVERY;

using SMTP_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::smtp::SMTP_Analyzer.")]] = zeek::analyzer::smtp::SMTP_Analyzer;

} // namespace analyzer::smtp
