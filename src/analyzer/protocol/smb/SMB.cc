#include "SMB.h"

using namespace analyzer::smb;

// This was 1<<17 originally but was changed due to larger messages
// being seen.
#define SMB_MAX_LEN (1<<18)

SMB_Analyzer::SMB_Analyzer(Connection *conn)
: tcp::TCP_ApplicationAnalyzer("SMB", conn)
	{
	chunks=0;
	interp=0;
	}

SMB_Analyzer::~SMB_Analyzer()
	{
	if ( interp )
		delete interp;
	}

void SMB_Analyzer::Done()
	{
	TCP_ApplicationAnalyzer::Done();

	if ( interp )
		{
		interp->FlowEOF(true);
		interp->FlowEOF(false);
		}
	}

void SMB_Analyzer::EndpointEOF(bool is_orig)
	{
	TCP_ApplicationAnalyzer::EndpointEOF(is_orig);

	if ( interp )
		interp->FlowEOF(is_orig);
	}

void SMB_Analyzer::Undelivered(uint64 seq, int len, bool orig)
	{
	TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	
	NeedResync();
	}

bool SMB_Analyzer::HasSMBHeader(int len, const u_char* data)
	{
	if ( len < 8 )
		return false;

	return (strncmp((const char*) data+4, "\xffSMB", 4) == 0 ||
	        strncmp((const char*) data+4, "\xfeSMB", 4) == 0);
	}

void SMB_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());

	// Either instantiate an interpreter or bail.
	if ( ! interp )
		{
		if ( HasSMBHeader(len, data) )
			interp = new binpac::SMB::SMB_Conn(this);
		else
			return;
		}

	try
		{
		// If we get here, it means we have an interpreter.
		interp->NewData(orig, data, data + len);

		// Let's assume that if there are no binpac exceptions after
		// 3 data chunks that this is probably actually SMB.
		if ( ++chunks == 3 )
			ProtocolConfirmation();
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		NeedResync();
		}
	}
