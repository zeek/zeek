// See the file "COPYING" in the main distribution directory for copyright.

#include "SSH.h"

#include "analyzer/protocol/tcp/TCP_Reassembler.h"

#include "Reporter.h"

#include "events.bif.h"

using namespace analyzer::SSH;

SSH_Analyzer::SSH_Analyzer(Connection* c)

: tcp::TCP_ApplicationAnalyzer("SSH", c)

	{
	interp = new binpac::SSH::SSH_Conn(this);
	had_gap = false;
	num_encrypted_packets_seen = 0;
	initial_client_packet_size = 0;
	initial_server_packet_size = 0;
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
	if (orig && !initial_client_packet_size)
		initial_client_packet_size = len;
	if (!orig && !initial_server_packet_size)
		initial_server_packet_size = len;
	
	int relative_len;
	if (orig)
	  	relative_len = len - initial_client_packet_size;
	else
	  	relative_len = len - initial_server_packet_size;

	if ( num_encrypted_packets_seen >= 6 )
		{
		int auth_result = AuthResult(relative_len, orig);
		if ( auth_result > 0 )
			{
			if ( auth_result == 1 )
				BifEvent::generate_ssh_auth_successful(interp->bro_analyzer(), interp->bro_analyzer()->Conn(),
					                                   packet_n_1_size, packet_n_2_size);
			if ( auth_result == 2 )
				BifEvent::generate_ssh_auth_failed(interp->bro_analyzer(), interp->bro_analyzer()->Conn(),
					                               packet_n_1_size, packet_n_2_size);
			}
		}
	if ( ( num_encrypted_packets_seen >= 2 ) &&
	     ( orig != packet_n_1_is_orig ) )
		{
		packet_n_2_is_orig = packet_n_1_is_orig;
		packet_n_2_size = packet_n_1_size;
		}
	
	if ( orig == packet_n_1_is_orig )
		 packet_n_1_size += len;
	else
		{
		packet_n_1_is_orig = orig;
		packet_n_1_size = relative_len;
		num_encrypted_packets_seen++;
		}
	}


int SSH_Analyzer::AuthResult(int len, bool orig)
	{
	if ( !orig && packet_n_1_is_orig && !packet_n_2_is_orig )
		{
		printf("Auth result = %d\n", len);
		if ( len == -16 )
			return 1;
		else if ( len >= 16 && len <= 32 )
			return 2;
		return 0;
		}	
	return -1;
	}

