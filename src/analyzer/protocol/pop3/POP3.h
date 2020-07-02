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

namespace analyzer { namespace pop3 {

typedef enum {
#include "POP3_cmd.def"
} POP3_Cmd;

typedef enum {
	POP3_START,
	POP3_AUTHORIZATION,
	POP3_TRANSACTION,
	POP3_UPDATE,
	POP3_FINISHED,
} POP3_MasterState;

typedef enum {
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
} POP3_State;

typedef enum {
	POP3_OK,
	POP3_WOK,
} POP3_SubState;

class POP3_Analyzer final : public tcp::TCP_ApplicationAnalyzer {
public:
	explicit POP3_Analyzer(Connection* conn);
	~POP3_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
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
	void POP3Event(EventHandlerPtr event, bool is_orig,
			const char* arg1 = nullptr, const char* arg2 = nullptr);

	mime::MIME_Mail* mail;
	std::list<std::string> cmds;

private:
	bool tls;
	tcp::ContentLine_Analyzer* cl_orig;
	tcp::ContentLine_Analyzer* cl_resp;
};

} } // namespace analyzer::*
