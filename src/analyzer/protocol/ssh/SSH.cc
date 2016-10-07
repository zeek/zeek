// See the file "COPYING" in the main distribution directory for copyright.

#include "SSH.h"

#include "analyzer/protocol/tcp/TCP_Reassembler.h"

#include "Reporter.h"

#include "types.bif.h"
#include "events.bif.h"

using namespace analyzer::SSH;

SSH_Analyzer::SSH_Analyzer(Connection* c)
	: tcp::TCP_ApplicationAnalyzer("SSH", c)
	{
	interp = new binpac::SSH::SSH_Conn(this);
	had_gap = false;
	auth_decision_made = false;
	skipped_banner = false;
	service_accept_size = 0;
	userauth_failure_size = 0;
	}

SSH_Analyzer::~SSH_Analyzer()
	{
	delete interp;
	}

void SSH_Analyzer::Done()
	{
	tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void SSH_Analyzer::EndpointEOF(bool is_orig)
	{
	tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void SSH_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());
	if ( TCP()->IsPartial() )
		return;

	if ( had_gap )
		// If only one side had a content gap, we could still try to
		// deliver data to the other side if the script layer can handle this.
		return;

	if ( interp->get_state(orig) == binpac::SSH::ENCRYPTED )
		{
		if ( ssh_encrypted_packet )
			BifEvent::generate_ssh_encrypted_packet(interp->bro_analyzer(), interp->bro_analyzer()->Conn(),
				orig, len);

		if ( ! auth_decision_made )
			ProcessEncrypted(len, orig);

		return;
		}

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void SSH_Analyzer::Undelivered(uint64 seq, int len, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
	interp->NewGap(orig, len);
	}

void SSH_Analyzer::ProcessEncrypted(int len, bool orig)
	{
	// We're interested in messages from the server for SSH2
	if ( ! orig && (interp->get_version() == binpac::SSH::SSH2) )
		{
		// The first thing we see and want to know is the length of
		// SSH_MSG_SERVICE_REQUEST, which has a fixed (decrypted) size
		// of 24 bytes (17 for content pad-aligned to 8-byte
		// boundaries)
		if ( ! service_accept_size )
			{
			service_accept_size = len;
			return;
			}

		// If our user can authenticate via the "none" method, this
		// packet will be a SSH_MSG_USERAUTH_SUCCESS, which has a
		// fixed (decrypted) size of 8 bytes (1 for content
		// pad-aligned to 8-byte boundaries). relative_len would be
		// -16.
		if ( ! userauth_failure_size && (len + 16 == service_accept_size) )
			{
			auth_decision_made = true;
			if ( ssh_auth_successful )
				BifEvent::generate_ssh_auth_successful(interp->bro_analyzer(), interp->bro_analyzer()->Conn(), true);
			return;
			}

		// Normally, this packet would be a SSH_MSG_USERAUTH_FAILURE
		// message, with a variable length, depending on the
		// authentication methods the server supports. If it's too
		// big, it might contain a pre-auth MOTD/banner, so we'll just
		// skip it.
		if ( ! userauth_failure_size )
			{
			if ( ! skipped_banner && (len - service_accept_size) > 256 )
				{
				skipped_banner = true;
				return;
				}
			userauth_failure_size = len;
			return;
			}

		// If we've already seen a failure, let's see if this is
		// another packet of the same size.
		if ( len == userauth_failure_size )
			{
			if ( ssh_auth_failed )
				BifEvent::generate_ssh_auth_failed(interp->bro_analyzer(), interp->bro_analyzer()->Conn());
			return;
			}

		// ...or a success packet.
		if ( len - service_accept_size == -16 )
			{
			auth_decision_made = true;
			if ( ssh_auth_successful )
				BifEvent::generate_ssh_auth_successful(interp->bro_analyzer(), interp->bro_analyzer()->Conn(), false);
			return;
			}
		}
	}
