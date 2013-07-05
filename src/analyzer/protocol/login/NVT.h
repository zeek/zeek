// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_LOGIN_NVT_H
#define ANALYZER_PROTOCOL_LOGIN_NVT_H

#include "analyzer/protocol/tcp/ContentLine.h"

#define TELNET_OPTION_BINARY 0
#define TELNET_OPTION_TERMINAL 24
#define TELNET_OPTION_AUTHENTICATE 37
#define TELNET_OPTION_ENCRYPT 38
#define TELNET_OPTION_ENVIRON 39
#define NUM_TELNET_OPTIONS 5

namespace analyzer { namespace login {

class NVT_Analyzer;

class TelnetOption {
public:
	TelnetOption(NVT_Analyzer* endp, unsigned int code);
	virtual ~TelnetOption() { }

// Whether we told the other side WILL/WONT/DO/DONT.
#define OPT_SAID_WILL 0x1
#define OPT_SAID_WONT 0x2
#define OPT_SAID_DO 0x4
#define OPT_SAID_DONT 0x8

	unsigned int Code() const	{ return code; }

	int IsActive() const		{ return active; }

	int SaidWill() const	{ return flags & OPT_SAID_WILL; }
	int SaidWont() const	{ return flags & OPT_SAID_WONT; }
	int SaidDo() const	{ return flags & OPT_SAID_DO; }
	int SaidDont() const	{ return flags & OPT_SAID_DONT; }

	void SetWill()	{ flags |= OPT_SAID_WILL; }
	void SetWont()	{ flags |= OPT_SAID_WONT; }
	void SetDo()	{ flags |= OPT_SAID_DO; }
	void SetDont()	{ flags |= OPT_SAID_DONT; }

	void RecvOption(unsigned int type);
	virtual void RecvSubOption(u_char* data, int len);

	virtual void SetActive(int is_active);

	const NVT_Analyzer* Endpoint() const	{ return endp; }

protected:
	friend class NVT_Analyzer;
	virtual void InconsistentOption(unsigned int type);
	virtual void BadOption();

	NVT_Analyzer* endp;
	unsigned int code;
	int flags;
	int active;
};

class TelnetTerminalOption : public TelnetOption {
public:
	TelnetTerminalOption(NVT_Analyzer* arg_endp)
		: TelnetOption(arg_endp, TELNET_OPTION_TERMINAL)	{ }

	void RecvSubOption(u_char* data, int len);
};

class TelnetEncryptOption : public TelnetOption {
public:
	TelnetEncryptOption(NVT_Analyzer* arg_endp)
		: TelnetOption(arg_endp, TELNET_OPTION_ENCRYPT)
			{ did_encrypt_request = doing_encryption = 0; }

	void RecvSubOption(u_char* data, int len);

	int DidRequest() const		{ return did_encrypt_request; }
	int DoingEncryption() const	{ return doing_encryption; }

protected:
	friend class NVT_Analyzer;
	int did_encrypt_request, doing_encryption;
};

class TelnetAuthenticateOption : public TelnetOption {
public:
	TelnetAuthenticateOption(NVT_Analyzer* arg_endp)
		: TelnetOption(arg_endp, TELNET_OPTION_AUTHENTICATE)
			{ authentication_requested = 0; }

	void RecvSubOption(u_char* data, int len);

	int DidRequestAuthentication() const
		{ return authentication_requested; }

protected:
	friend class NVT_Analyzer;
	int authentication_requested;
};

class TelnetEnvironmentOption : public TelnetOption {
public:
	TelnetEnvironmentOption(NVT_Analyzer* arg_endp)
		: TelnetOption(arg_endp, TELNET_OPTION_ENVIRON)
			{ }

	void RecvSubOption(u_char* data, int len);

protected:
	char* ExtractEnv(u_char*& data, int& len, int& code);
};

class TelnetBinaryOption : public TelnetOption {
public:
	TelnetBinaryOption(NVT_Analyzer* arg_endp)
		: TelnetOption(arg_endp, TELNET_OPTION_BINARY)
			{ }

	void SetActive(int is_active);

protected:
	void InconsistentOption(unsigned int type);
};

class NVT_Analyzer : public tcp::ContentLine_Analyzer {
public:
	NVT_Analyzer(Connection* conn, bool orig);
	~NVT_Analyzer();

	TelnetOption* FindOption(unsigned int code);
	TelnetOption* FindPeerOption(unsigned int code);

	void SetPeer(NVT_Analyzer* arg_peer)	{ peer = arg_peer; }

	void AuthenticationAccepted();
	void AuthenticationRejected();

	void SetTerminal(const u_char* terminal, int len);
	void SetBinaryMode(int mode)	{ binary_mode = mode; }
	void SetEncrypting(int mode);
	void SetAuthName(char* arg_auth_name)	{ auth_name = arg_auth_name; }

	const char* AuthName() const	{ return auth_name; }
	int AuthenticationHasBeenAccepted() const
		{ return authentication_has_been_accepted; }

protected:
	void DoDeliver(int len, const u_char* data);

	void ScanOption(int seq, int len, const u_char* data);
	virtual void SawOption(unsigned int code);
	virtual void SawOption(unsigned int code, unsigned int subcode);
	virtual void SawSubOption(const char* opt, int len);
	virtual void BadOptionTermination(unsigned int code);
	const char* PeerAuthName() const;

	NVT_Analyzer* peer;

	int pending_IAC;	// true if we're working on an option/IAC
	int IAC_pos;		// where the IAC was seen
	int is_suboption;	// true if current option is suboption
	int last_was_IAC;	// for scanning suboptions

	int binary_mode, encrypting_mode;
	int authentication_has_been_accepted;	// if true, we accepted peer's authentication
	char* auth_name;

	TelnetOption* options[NUM_TELNET_OPTIONS];
	int num_options;
};

} } // namespace analyzer::* 

#endif
