// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/analyzer/protocol/tcp/ContentLine.h"

#define TELNET_OPTION_BINARY 0
#define TELNET_OPTION_TERMINAL 24
#define TELNET_OPTION_AUTHENTICATE 37
#define TELNET_OPTION_ENCRYPT 38
#define TELNET_OPTION_ENVIRON 39
#define NUM_TELNET_OPTIONS 5

ZEEK_FORWARD_DECLARE_NAMESPACED(NVT_Analyzer, zeek, analyzer::login);

namespace zeek::analyzer::login {

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

	bool IsActive() const		{ return active; }

	bool SaidWill() const	{ return flags & OPT_SAID_WILL; }
	bool SaidWont() const	{ return flags & OPT_SAID_WONT; }
	bool SaidDo() const	{ return flags & OPT_SAID_DO; }
	bool SaidDont() const	{ return flags & OPT_SAID_DONT; }

	void SetWill()	{ flags |= OPT_SAID_WILL; }
	void SetWont()	{ flags |= OPT_SAID_WONT; }
	void SetDo()	{ flags |= OPT_SAID_DO; }
	void SetDont()	{ flags |= OPT_SAID_DONT; }

	void RecvOption(unsigned int type);
	virtual void RecvSubOption(u_char* data, int len);

	virtual void SetActive(bool is_active);

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

namespace detail {

class TelnetTerminalOption final : public TelnetOption {
public:
	explicit TelnetTerminalOption(NVT_Analyzer* arg_endp)
		: TelnetOption(arg_endp, TELNET_OPTION_TERMINAL)	{ }

	void RecvSubOption(u_char* data, int len) override;
};

class TelnetEncryptOption final : public TelnetOption {
public:
	explicit TelnetEncryptOption(NVT_Analyzer* arg_endp)
		: TelnetOption(arg_endp, TELNET_OPTION_ENCRYPT)
			{ did_encrypt_request = doing_encryption = 0; }

	void RecvSubOption(u_char* data, int len) override;

	int DidRequest() const		{ return did_encrypt_request; }
	int DoingEncryption() const	{ return doing_encryption; }

protected:
	friend class NVT_Analyzer;
	int did_encrypt_request, doing_encryption;
};

class TelnetAuthenticateOption final : public TelnetOption {
public:
	explicit TelnetAuthenticateOption(NVT_Analyzer* arg_endp)
		: TelnetOption(arg_endp, TELNET_OPTION_AUTHENTICATE)
			{ authentication_requested = 0; }

	void RecvSubOption(u_char* data, int len) override;

	int DidRequestAuthentication() const
		{ return authentication_requested; }

protected:
	friend class NVT_Analyzer;
	int authentication_requested;
};

class TelnetEnvironmentOption final : public TelnetOption {
public:
	explicit TelnetEnvironmentOption(NVT_Analyzer* arg_endp)
		: TelnetOption(arg_endp, TELNET_OPTION_ENVIRON)
			{ }

	void RecvSubOption(u_char* data, int len) override;

protected:
	char* ExtractEnv(u_char*& data, int& len, int& code);
};

class TelnetBinaryOption final : public TelnetOption {
public:
	explicit TelnetBinaryOption(NVT_Analyzer* arg_endp)
		: TelnetOption(arg_endp, TELNET_OPTION_BINARY)
			{ }

	void SetActive(bool is_active) override;

protected:
	void InconsistentOption(unsigned int type) override;
};

} // namespace detail

class NVT_Analyzer final : public analyzer::tcp::ContentLine_Analyzer {
public:
	NVT_Analyzer(Connection* conn, bool orig);
	~NVT_Analyzer() override;

	TelnetOption* FindOption(unsigned int code);
	TelnetOption* FindPeerOption(unsigned int code);

	void SetPeer(NVT_Analyzer* arg_peer)	{ peer = arg_peer; }

	void AuthenticationAccepted();
	void AuthenticationRejected();

	void SetTerminal(const u_char* terminal, int len);
	void SetBinaryMode(int mode)	{ binary_mode = mode; }
	void SetEncrypting(int mode);
	void SetAuthName(char* arg_auth_name)	{ delete [] auth_name; auth_name = arg_auth_name; }

	const char* AuthName() const	{ return auth_name; }
	int AuthenticationHasBeenAccepted() const
		{ return authentication_has_been_accepted; }

protected:
	void DoDeliver(int len, const u_char* data) override;
	void DeliverChunk(int& len, const u_char*& data);

	void ScanOption(int& len, const u_char*& data);
	virtual void SawOption(unsigned int code);
	virtual void SawOption(unsigned int code, unsigned int subcode);
	virtual void SawSubOption(const char* opt, int len);
	virtual void BadOptionTermination(unsigned int code);
	const char* PeerAuthName() const;

	NVT_Analyzer* peer = nullptr;

	int IAC_pos = 0;		// where the IAC was seen
	bool pending_IAC = false;	// true if we're working on an option/IAC
	bool is_suboption = false;	// true if current option is suboption
	bool last_was_IAC = false;	// for scanning suboptions
	bool authentication_has_been_accepted = false;	// if true, we accepted peer's authentication

	int binary_mode = 0;
	int encrypting_mode = 0;
	char* auth_name = nullptr;

	TelnetOption* options[NUM_TELNET_OPTIONS];
	int num_options = 0;
};

} // namespace zeek::analyzer::login
