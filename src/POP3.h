// This code contributed to Bro by Florian Schimandl and Hugh Dollman.
//
// An analyser for the POP3 protocol.

#ifndef pop3_h
#define pop3_h

#include <vector>
#include <string>
#include <algorithm>

#include "NVT.h"
#include "TCP.h"
#include "MIME.h"


#undef POP3_CMD_DEF
#define POP3_CMD_DEF(cmd)	POP3_CMD_##cmd,

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

class POP3_Analyzer : public TCP_ApplicationAnalyzer {
public:
	POP3_Analyzer(Connection* conn);
	~POP3_Analyzer();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{
		return new POP3_Analyzer(conn);
		}

	static bool Available()
		{
		return pop3_request || pop3_reply || pop3_data || pop3_unexpected;
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

	string user;
	string password;

	void ProcessRequest(int length, const char* line);
	void ProcessReply(int length, const char* line);
	void NotAllowed(const char* cmd, const char* state);
	void ProcessClientCmd();
	void FinishClientCmd();
	void BeginData();
	void ProcessData(int length, const char* line);
	void EndData();

	vector<string> TokenizeLine(const string input, const char split);
	int ParseCmd(string cmd);
	void AuthSuccessfull();
	void POP3Event(EventHandlerPtr event, bool is_orig,
			const char* arg1 = 0, const char* arg2 = 0);

	MIME_Mail* mail;
	list<string> cmds;

private:
	bool backOff;
};

#endif
