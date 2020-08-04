// This code contributed to Bro by Florian Schimandl and Hugh Dollman.
//
// An analyser for the POP3 protocol.

#pragma once

#include <vector>
#include <string>
#include <algorithm>

#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/tcp/ContentLine.h"
#include "analyzer/protocol/login/NVT.h"
#include "analyzer/protocol/mime/MIME.h"

#undef POP3_CMD_DEF
#define POP3_CMD_DEF(cmd)	POP3_CMD_##cmd,

namespace zeek::analyzer::pop3 {
namespace detail {

enum POP3_Cmd {
#include "POP3_cmd.def"
};

enum POP3_MasterState {
	POP3_START,
	POP3_AUTHORIZATION,
	POP3_TRANSACTION,
	POP3_UPDATE,
	POP3_FINISHED,
};

enum POP3_State {
	START,
	USER,
	PASS,
	APOP,
	AUTH,
	AUTH_PLAIN,
	AUTH_LOGIN,
	AUTH_CRAM_MD5,
	NOOP,
	LAST,
	STAT,
	LIST,
	RETR,
	DELE,
	UIDL,
	TOP,
	QUIT,
	RSET,
	CAPA,
	STLS,
	XSENDER,
	MISC,
	END,
};

enum POP3_SubState {
	POP3_OK,
	POP3_WOK,
};

} // namespace detail

class POP3_Analyzer final : public zeek::analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	explicit POP3_Analyzer(zeek::Connection* conn);
	~POP3_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;

	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{
		return new POP3_Analyzer(conn);
		}

protected:
	int masterState;
	int subState;
	int state;
	int lastState;
	bool multiLine;
	bool guessing;
	bool requestForMultiLine;
	bool waitingForAuthentication;
	int lastRequiredCommand;
	int authLines;

	std::string user;
	std::string password;

	void ProcessRequest(int length, const char* line);
	void ProcessReply(int length, const char* line);
	void NotAllowed(const char* cmd, const char* state);
	void ProcessClientCmd();
	void FinishClientCmd();
	void BeginData(bool orig);
	void ProcessData(int length, const char* line);
	void EndData();
	void StartTLS();

	std::vector<std::string> TokenizeLine(const std::string& input, char split);
	int ParseCmd(std::string cmd);
	void AuthSuccessfull();
	void POP3Event(zeek::EventHandlerPtr event, bool is_orig,
	               const char* arg1 = nullptr, const char* arg2 = nullptr);

	zeek::analyzer::mime::MIME_Mail* mail;
	std::list<std::string> cmds;

private:
	bool tls;
	zeek::analyzer::tcp::ContentLine_Analyzer* cl_orig;
	zeek::analyzer::tcp::ContentLine_Analyzer* cl_resp;
};

} // namespace zeek::analyzer::pop3

namespace analyzer::pop3 {

using POP3_Cmd [[deprecated("Remove in v4.1. Use zeek::analyzer::pop3::detail::POP3_Cmd.")]] = zeek::analyzer::pop3::detail::POP3_Cmd;
// These values are from a #include above

using POP3_MasterState [[deprecated("Remove in v4.1. Use zeek::analyzer::pop3::detail::POP3_MasterState.")]] = zeek::analyzer::pop3::detail::POP3_MasterState;
constexpr auto POP3_START [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::POP3_START.")]] = zeek::analyzer::pop3::detail::POP3_START;
constexpr auto POP3_AUTHORIZATION [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::POP3_AUTHORIZATION.")]] = zeek::analyzer::pop3::detail::POP3_AUTHORIZATION;
constexpr auto POP3_TRANSACTION [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::POP3_TRANSACTION.")]] = zeek::analyzer::pop3::detail::POP3_TRANSACTION;
constexpr auto POP3_UPDATE [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::POP3_UPDATE.")]] = zeek::analyzer::pop3::detail::POP3_UPDATE;
constexpr auto POP3_FINISHED [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::POP3_FINISHED.")]] = zeek::analyzer::pop3::detail::POP3_FINISHED;

using POP3_State [[deprecated("Remove in v4.1. Use zeek::analyzer::pop3::detail::POP3_State.")]] = zeek::analyzer::pop3::detail::POP3_State;
constexpr auto START [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::START.")]] = zeek::analyzer::pop3::detail::START;
constexpr auto USER [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::USER.")]] = zeek::analyzer::pop3::detail::USER;
constexpr auto PASS [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::PASS.")]] = zeek::analyzer::pop3::detail::PASS;
constexpr auto APOP [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::APOP.")]] = zeek::analyzer::pop3::detail::APOP;
constexpr auto AUTH [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::AUTH.")]] = zeek::analyzer::pop3::detail::AUTH;
constexpr auto AUTH_PLAIN [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::AUTH_PLAIN.")]] = zeek::analyzer::pop3::detail::AUTH_PLAIN;
constexpr auto AUTH_LOGIN [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::AUTH_LOGIN.")]] = zeek::analyzer::pop3::detail::AUTH_LOGIN;
constexpr auto AUTH_CRAM_MD5 [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::AUTH_CRAM_MD5.")]] = zeek::analyzer::pop3::detail::AUTH_CRAM_MD5;
constexpr auto NOOP [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::NOOP.")]] = zeek::analyzer::pop3::detail::NOOP;
constexpr auto LAST [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::LAST.")]] = zeek::analyzer::pop3::detail::LAST;
constexpr auto STAT [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::STAT.")]] = zeek::analyzer::pop3::detail::STAT;
constexpr auto LIST [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::LIST.")]] = zeek::analyzer::pop3::detail::LIST;
constexpr auto RETR [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::RETR.")]] = zeek::analyzer::pop3::detail::RETR;
constexpr auto DELE [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::DELE.")]] = zeek::analyzer::pop3::detail::DELE;
constexpr auto UIDL [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::UIDL.")]] = zeek::analyzer::pop3::detail::UIDL;
constexpr auto TOP [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::TOP.")]] = zeek::analyzer::pop3::detail::TOP;
constexpr auto QUIT [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::QUIT.")]] = zeek::analyzer::pop3::detail::QUIT;
constexpr auto RSET [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::RSET.")]] = zeek::analyzer::pop3::detail::RSET;
constexpr auto CAPA [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::CAPA.")]] = zeek::analyzer::pop3::detail::CAPA;
constexpr auto STLS [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::STLS.")]] = zeek::analyzer::pop3::detail::STLS;
constexpr auto XSENDER [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::XSENDER.")]] = zeek::analyzer::pop3::detail::XSENDER;
constexpr auto MISC [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::MISC.")]] = zeek::analyzer::pop3::detail::MISC;
constexpr auto END [[deprecated("Remove in v4.1. Uze zeek::analyzer::pop3::detail::END.")]] = zeek::analyzer::pop3::detail::END;

using POP3_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::pop3::POP3_Analyzer.")]] = zeek::analyzer::pop3::POP3_Analyzer;

} // namespace analyzer::pop3
