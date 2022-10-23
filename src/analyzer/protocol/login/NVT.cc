// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/login/NVT.h"

#include "zeek/zeek-config.h"

#include <cstdlib>

#include "zeek/Event.h"
#include "zeek/NetVar.h"
#include "zeek/Reporter.h"
#include "zeek/ZeekString.h"
#include "zeek/analyzer/protocol/login/events.bif.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

#define IS_3_BYTE_OPTION(c) (c >= 251 && c <= 254)

#define TELNET_OPT_SB 250
#define TELNET_OPT_SE 240

#define TELNET_OPT_IS 0
#define TELNET_OPT_SEND 1

#define TELNET_OPT_WILL 251
#define TELNET_OPT_WONT 252
#define TELNET_OPT_DO 253
#define TELNET_OPT_DONT 254

#define TELNET_IAC 255

namespace zeek::analyzer::login
	{

TelnetOption::TelnetOption(NVT_Analyzer* arg_endp, unsigned int arg_code)
	{
	endp = arg_endp;
	code = arg_code;
	flags = 0;
	active = 0;
	}

void TelnetOption::RecvOption(unsigned int type)
	{
	TelnetOption* peer = endp->FindPeerOption(code);

	if ( ! peer )
		{
		reporter->AnalyzerError(endp, "option peer missing in TelnetOption::RecvOption");
		return;
		}

	// WILL/WONT/DO/DONT are messages we've *received* from our peer.
	switch ( type )
		{
		case TELNET_OPT_WILL:
			if ( SaidDont() || peer->SaidWont() || peer->IsActive() )
				InconsistentOption(type);

			peer->SetWill();

			if ( SaidDo() )
				peer->SetActive(true);
			break;

		case TELNET_OPT_WONT:
			if ( peer->SaidWill() && ! SaidDont() )
				InconsistentOption(type);

			peer->SetWont();

			if ( SaidDont() )
				peer->SetActive(false);
			break;

		case TELNET_OPT_DO:
			if ( SaidWont() || peer->SaidDont() || IsActive() )
				InconsistentOption(type);

			peer->SetDo();

			if ( SaidWill() )
				SetActive(true);
			break;

		case TELNET_OPT_DONT:
			if ( peer->SaidDo() && ! SaidWont() )
				InconsistentOption(type);

			peer->SetDont();

			if ( SaidWont() )
				SetActive(false);
			break;

		default:
			reporter->AnalyzerError(endp, "bad option type in TelnetOption::RecvOption");
			return;
		}
	}

void TelnetOption::RecvSubOption(u_char* /* data */, int /* len */) { }

void TelnetOption::SetActive(bool is_active)
	{
	active = is_active;
	}

void TelnetOption::InconsistentOption(unsigned int /* type */)
	{
	endp->Event(inconsistent_option);
	}

void TelnetOption::BadOption()
	{
	endp->Event(bad_option);
	}

namespace detail
	{

void TelnetTerminalOption::RecvSubOption(u_char* data, int len)
	{
	if ( len <= 0 )
		{
		BadOption();
		return;
		}

	if ( data[0] == TELNET_OPT_SEND )
		return;

	if ( data[0] != TELNET_OPT_IS )
		{
		BadOption();
		return;
		}

	endp->SetTerminal(data + 1, len - 1);
	}

#define ENCRYPT_SET_ALGORITHM 0
#define ENCRYPT_SUPPORT_ALGORITHM 1
#define ENCRYPT_REPLY 2
#define ENCRYPT_STARTING_TO_ENCRYPT 3
#define ENCRYPT_NO_LONGER_ENCRYPTING 4
#define ENCRYPT_REQUEST_START_TO_ENCRYPT 5
#define ENCRYPT_REQUEST_NO_LONGER_ENCRYPT 6
#define ENCRYPT_ENCRYPT_KEY 7
#define ENCRYPT_DECRYPT_KEY 8

void TelnetEncryptOption::RecvSubOption(u_char* data, int len)
	{
	if ( ! active )
		{
		InconsistentOption(0);
		return;
		}

	if ( len <= 0 )
		{
		BadOption();
		return;
		}

	unsigned int opt = data[0];

	if ( opt == ENCRYPT_REQUEST_START_TO_ENCRYPT )
		++did_encrypt_request;

	else if ( opt == ENCRYPT_STARTING_TO_ENCRYPT )
		{
		TelnetEncryptOption* peer = (TelnetEncryptOption*)endp->FindPeerOption(code);

		if ( ! peer )
			{
			reporter->AnalyzerError(endp,
			                        "option peer missing in TelnetEncryptOption::RecvSubOption");
			return;
			}

		if ( peer->DidRequest() || peer->DoingEncryption() ||
		     peer->Endpoint()->AuthenticationHasBeenAccepted() )
			{
			endp->SetEncrypting(1);
			++doing_encryption;
			}
		else
			InconsistentOption(0);
		}
	}

#define HERE_IS_AUTHENTICATION 0
#define SEND_ME_AUTHENTICATION 1
#define AUTHENTICATION_STATUS 2
#define AUTHENTICATION_NAME 3

#define AUTH_REJECT 1
#define AUTH_ACCEPT 2

void TelnetAuthenticateOption::RecvSubOption(u_char* data, int len)
	{
	if ( len <= 0 )
		{
		BadOption();
		return;
		}

	switch ( data[0] )
		{
		case HERE_IS_AUTHENTICATION:
			{
			TelnetAuthenticateOption* peer = (TelnetAuthenticateOption*)endp->FindPeerOption(code);

			if ( ! peer )
				{
				reporter->AnalyzerError(
					endp, "option peer missing in TelnetAuthenticateOption::RecvSubOption");
				return;
				}

			if ( ! peer->DidRequestAuthentication() )
				InconsistentOption(0);
			}
			break;

		case SEND_ME_AUTHENTICATION:
			++authentication_requested;
			break;

		case AUTHENTICATION_STATUS:
			if ( len <= 1 )
				{
				BadOption();
				return;
				}

			if ( data[1] == AUTH_REJECT )
				endp->AuthenticationRejected();
			else if ( data[1] == AUTH_ACCEPT )
				endp->AuthenticationAccepted();
			else
				{
				// Don't complain, there may be replies we don't
				// know about.
				}
			break;

		case AUTHENTICATION_NAME:
			{
			char* auth_name = new char[len];
			util::safe_strncpy(auth_name, (char*)data + 1, len);
			endp->SetAuthName(auth_name);
			}
			break;

		default:
			BadOption();
		}
	}

#define ENVIRON_IS 0
#define ENVIRON_SEND 1
#define ENVIRON_INFO 2

#define ENVIRON_VAR 0
#define ENVIRON_VAL 1
#define ENVIRON_ESC 2
#define ENVIRON_USERVAR 3

void TelnetEnvironmentOption::RecvSubOption(u_char* data, int len)
	{
	if ( len <= 0 )
		{
		BadOption();
		return;
		}

	if ( data[0] == ENVIRON_SEND )
		//### We should track the dialog and make sure both sides agree.
		return;

	if ( data[0] != ENVIRON_IS && data[0] != ENVIRON_INFO )
		{
		BadOption();
		return;
		}

	--len; // Discard code.
	++data;

	while ( len > 0 )
		{
		int code1, code2;
		char* var_name = ExtractEnv(data, len, code1);
		char* var_val = ExtractEnv(data, len, code2);

		if ( ! var_name || ! var_val || (code1 != ENVIRON_VAR && code1 != ENVIRON_USERVAR) ||
		     code2 != ENVIRON_VAL )
			{
			// One of var_name/var_val might be set; avoid leak.
			delete[] var_name;
			delete[] var_val;

			BadOption();
			break;
			}

		static_cast<analyzer::tcp::TCP_ApplicationAnalyzer*>(endp->Parent())
			->SetEnv(endp->IsOrig(), var_name, var_val);
		}
	}

char* TelnetEnvironmentOption::ExtractEnv(u_char*& data, int& len, int& code)
	{
	code = data[0];

	if ( code != ENVIRON_VAR && code != ENVIRON_VAL && code != ENVIRON_USERVAR )
		return nullptr;

	// Move past code.
	--len;
	++data;

	// Find the end of this piece of the option.
	u_char* data_end = data + len;
	u_char* d;
	for ( d = data; d < data_end; ++d )
		{
		if ( *d == ENVIRON_VAR || *d == ENVIRON_VAL || *d == ENVIRON_USERVAR )
			break;

		if ( *d == ENVIRON_ESC )
			{
			++d; // move past ESC
			if ( d >= data_end )
				return nullptr;
			break;
			}
		}

	int size = d - data;
	char* env = new char[size + 1];

	// Now copy into env.
	int d_ind = 0;
	int i;
	for ( i = 0; i < size; ++i )
		{
		if ( data[d_ind] == ENVIRON_ESC )
			++d_ind;

		env[i] = data[d_ind];
		++d_ind;
		}

	env[i] = '\0';

	data = d;
	len -= size;

	return env;
	}

void TelnetBinaryOption::SetActive(bool is_active)
	{
	endp->SetBinaryMode(is_active);
	active = is_active;
	}

void TelnetBinaryOption::InconsistentOption(unsigned int /* type */)
	{
	// I don't know why, but this gets turned on redundantly -
	// doesn't do any harm, so ignore it.  Example is
	// in ex/redund-binary-opt.trace.
	}

	} // namespace detail

NVT_Analyzer::NVT_Analyzer(Connection* conn, bool orig)
	: analyzer::tcp::ContentLine_Analyzer("NVT", conn, orig), options()
	{
	}

NVT_Analyzer::~NVT_Analyzer()
	{
	for ( int i = 0; i < num_options; ++i )
		delete options[i];

	delete[] auth_name;
	}

TelnetOption* NVT_Analyzer::FindOption(unsigned int code)
	{
	int i;
	for ( i = 0; i < num_options; ++i )
		if ( options[i]->Code() == code )
			return options[i];

	TelnetOption* opt = nullptr;
	if ( i < NUM_TELNET_OPTIONS )
		{ // Maybe we haven't created this option yet.
		switch ( code )
			{
			case TELNET_OPTION_BINARY:
				opt = new detail::TelnetBinaryOption(this);
				break;

			case TELNET_OPTION_TERMINAL:
				opt = new detail::TelnetTerminalOption(this);
				break;

			case TELNET_OPTION_ENCRYPT:
				opt = new detail::TelnetEncryptOption(this);
				break;

			case TELNET_OPTION_AUTHENTICATE:
				opt = new detail::TelnetAuthenticateOption(this);
				break;

			case TELNET_OPTION_ENVIRON:
				opt = new detail::TelnetEnvironmentOption(this);
				break;
			}
		}

	if ( opt )
		options[num_options++] = opt;

	return opt;
	}

TelnetOption* NVT_Analyzer::FindPeerOption(unsigned int code)
	{
	assert(peer);
	return peer->FindOption(code);
	}

void NVT_Analyzer::AuthenticationAccepted()
	{
	authentication_has_been_accepted = true;
	Event(authentication_accepted, PeerAuthName());
	}

void NVT_Analyzer::AuthenticationRejected()
	{
	authentication_has_been_accepted = false;
	Event(authentication_rejected, PeerAuthName());
	}

const char* NVT_Analyzer::PeerAuthName() const
	{
	assert(peer);
	return peer->AuthName();
	}

void NVT_Analyzer::SetTerminal(const u_char* terminal, int len)
	{
	if ( login_terminal )
		EnqueueConnEvent(login_terminal, ConnVal(),
		                 make_intrusive<StringVal>(new String(terminal, len, false)));
	}

void NVT_Analyzer::SetEncrypting(int mode)
	{
	encrypting_mode = mode;
	SetSkipDeliveries(mode);
	if ( mode )
		Event(activating_encryption);
	}

#define MAX_DELIVER_UNIT 128

void NVT_Analyzer::DoDeliver(int len, const u_char* data)
	{
	while ( len > 0 )
		{
		if ( pending_IAC )
			ScanOption(len, data);
		else
			DeliverChunk(len, data);
		}
	}

void NVT_Analyzer::DeliverChunk(int& len, const u_char*& data)
	{
	// This code is very similar to that for TCP_ContentLine.  We
	// don't virtualize out the differences because some of them
	// would require per-character function calls, too expensive.

	// Add data up to IAC or end.
	for ( ; len > 0; --len, ++data )
		{
		if ( offset >= buf_len )
			InitBuffer(buf_len * 2);

		int c = data[0];

		if ( binary_mode && c != TELNET_IAC )
			c &= 0x7f;

#define EMIT_LINE                                                                                  \
		{                                                                                          \
		buf[offset] = '\0';                                                                        \
		ForwardStream(offset, buf, IsOrig());                                                      \
		offset = 0;                                                                                \
		}

		switch ( c )
			{
			case '\r':
				if ( CRLFAsEOL() & CR_as_EOL )
					EMIT_LINE
				else
					buf[offset++] = c;
				break;

			case '\n':
				if ( last_char == '\r' )
					{
					if ( CRLFAsEOL() & CR_as_EOL )
						// we already emited, skip
						;
					else
						{
						--offset; // remove '\r'
						EMIT_LINE
						}
					}

				else if ( CRLFAsEOL() & LF_as_EOL )
					EMIT_LINE

				else
					{
					if ( Conn()->FlagEvent(SINGULAR_LF) )
						Weird("line_terminated_with_single_LF");
					buf[offset++] = c;
					}
				break;

			case '\0':
				if ( last_char == '\r' )
					// Allow a NUL just after a \r - Solaris
					// Telnet servers generate these, and they
					// appear harmless.
					;

				else if ( flag_NULs )
					CheckNUL();

				else
					buf[offset++] = c;
				break;

			case TELNET_IAC:
				pending_IAC = true;
				IAC_pos = offset;
				is_suboption = false;
				buf[offset++] = c;
				--len;
				++data;
				ScanOption(len, data);
				return;

			default:
				buf[offset++] = c;
				break;
			}

		if ( ! (CRLFAsEOL() & CR_as_EOL) && last_char == '\r' && c != '\n' && c != '\0' )
			{
			if ( Conn()->FlagEvent(SINGULAR_CR) )
				Weird("line_terminated_with_single_CR");
			}

		last_char = c;
		}
	}

void NVT_Analyzer::ScanOption(int& len, const u_char*& data)
	{
	if ( len <= 0 )
		return;

	if ( IAC_pos == offset - 1 )
		{ // All we've seen so far is the IAC.
		unsigned int code = data[0];

		if ( code == TELNET_IAC )
			{
			// An escaped 255, throw away the second
			// instance and drop the IAC state.
			pending_IAC = false;
			last_char = code;
			}

		else if ( code == TELNET_OPT_SB )
			{
			is_suboption = true;
			last_was_IAC = false;

			if ( offset >= buf_len )
				InitBuffer(buf_len * 2);

			buf[offset++] = code;
			}

		else if ( IS_3_BYTE_OPTION(code) )
			{
			is_suboption = false;

			if ( offset >= buf_len )
				InitBuffer(buf_len * 2);

			buf[offset++] = code;
			}

		else
			{
			// We've got the whole 2-byte option.
			SawOption(code);

			// Throw it and the IAC away.
			--offset;
			pending_IAC = false;
			}

		--len;
		++data;
		return;
		}

	if ( ! is_suboption )
		{
		// We now have the full 3-byte option.
		SawOption(u_char(buf[offset - 1]), data[0]);

		// Delete the option.
		offset -= 2; // code + IAC
		pending_IAC = false;

		--len;
		++data;
		return;
		}

	// A suboption.  Spin looking for end.
	for ( ; len > 0; --len, ++data )
		{
		if ( offset >= buf_len )
			InitBuffer(buf_len * 2);

		unsigned int code = data[0];

		if ( last_was_IAC )
			{
			last_was_IAC = false;

			if ( code == TELNET_IAC )
				{
				// This is an escaped IAC, eat
				// the second copy.
				continue;
				}

			if ( code != TELNET_OPT_SE )
				// BSD Telnet treats this case as terminating
				// the suboption, so that's what we do here
				// too.  Below we make sure to munch on the
				// new IAC.
				BadOptionTermination(code);

			int opt_start = IAC_pos + 2;
			int opt_stop = offset - 1;
			int opt_len = opt_stop - opt_start;
			SawSubOption((const char*)&buf[opt_start], opt_len);

			// Delete suboption.
			offset = IAC_pos;
			pending_IAC = is_suboption = false;

			if ( code == TELNET_OPT_SE )
				{
				--len;
				++data;
				}
			else
				{
				// Munch on the new (broken) option.
				pending_IAC = true;
				IAC_pos = offset;
				buf[offset++] = TELNET_IAC;
				}
			return;
			}

		else
			{
			buf[offset++] = code;
			last_was_IAC = (code == TELNET_IAC);
			}
		}
	}

void NVT_Analyzer::SawOption(unsigned int /* code */) { }

void NVT_Analyzer::SawOption(unsigned int code, unsigned int subcode)
	{
	TelnetOption* opt = FindOption(subcode);
	if ( opt )
		opt->RecvOption(code);
	}

void NVT_Analyzer::SawSubOption(const char* subopt, int len)
	{
	unsigned int subcode = u_char(subopt[0]);

	++subopt;
	--len;

	TelnetOption* opt = FindOption(subcode);
	if ( opt )
		opt->RecvSubOption((u_char*)subopt, len);
	}

void NVT_Analyzer::BadOptionTermination(unsigned int /* code */)
	{
	Event(bad_option_termination);
	}

	} // namespace zeek::analyzer::login
