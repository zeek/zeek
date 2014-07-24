#include "SMB.h"

using namespace analyzer::smb;

// This was 1<<17 originally but was changed due to larger messages
// being seen.
#define SMB_MAX_LEN (1<<18)

SMB_Analyzer::SMB_Analyzer(Connection *conn)
: tcp::TCP_ApplicationAnalyzer("SMB", conn)
	{
	chunks=0;
	interp = new binpac::SMB::SMB_Conn(this);
	AddSupportAnalyzer(new Contents_SMB(conn, true));
	AddSupportAnalyzer(new Contents_SMB(conn, false));
}

SMB_Analyzer::~SMB_Analyzer()
	{
	delete interp;
	}

void SMB_Analyzer::Done()
	{
	TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void SMB_Analyzer::EndpointEOF(bool is_orig)
	{
	TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}
	
void SMB_Analyzer::Undelivered(uint64 seq, int len, bool orig)
	{
	TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	interp->NewGap(orig, len);
	}

void SMB_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());

	try 
		{
		interp->NewData(orig, data, data + len);
		// Let's assume that if there are no binpac exceptions after 
		// 3 data chunks that this is probably actually SMB.
		if ( chunks >= 3 )
			ProtocolConfirmation();
		else
			++chunks;
		}
	catch ( const binpac::Exception& e )
		{
		  ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		  //printf(fmt("Binpac exception: %s", e.c_msg()));
		}
	}



Contents_SMB::Contents_SMB(Connection* conn, bool orig)
: TCP_SupportAnalyzer("Contents_SMB", conn, orig)
	{
	state = WAIT_FOR_HDR;
	resync_state = INSYNC;
	first_time = last_time = 0.0;
	msg_len = 0;
	msg_type = 0;
	}

void Contents_SMB::Init()
	{
	TCP_SupportAnalyzer::Init();

	NeedResync();
	}

Contents_SMB::~Contents_SMB()
	{
	}


void Contents_SMB::Undelivered(uint64 seq, int len, bool orig)
	{
	TCP_SupportAnalyzer::Undelivered(seq, len, orig);
	NeedResync();
	}

bool Contents_SMB::HasSMBHeader(const u_char* data)
	{
	return (strncmp((const char*) data+4, "\xffSMB", 4) == 0 ||
	        strncmp((const char*) data+4, "\xfeSMB", 4) == 0);
	}

void Contents_SMB::DeliverSMB(int len, const u_char* data)
	{
	// Check the 4-byte header.
	if ( ! HasSMBHeader(data) )
		{
		Conn()->Weird(fmt("SMB-over-TCP header error: %02x %05x, >>\\x%02x%c%c%c<<",
			//dshdr[0], dshdr[1], dshdr[2], dshdr[3],
			msg_type, msg_len,
			data[0], data[1], data[2], data[3]));
		NeedResync();
		}
	else
		{
		ForwardStream(len, data, IsOrig());
		}
	}

bool Contents_SMB::CheckResync(int& len, const u_char*& data, bool orig)
	{
	if (resync_state == INSYNC)
		return true;

	// This is an attempt to re-synchronize the stream after a content gap.  
	// Returns true if we are in sync. 
	// Returns false otherwise (we are in resync mode)
	//
	// We try to look for the beginning of a SMB message, assuming 
	// SMB messages start at packet boundaries (though they may span 
	// over multiple packets) (note that the data* of DeliverStream()
	// usually starts at a packet boundrary). 
	//
	// Now lets see whether data points to the beginning of a
	// SMB message. If the resync processs is successful, we should
	// be at the beginning of a frame.

	// check if the SMB header starts with an SMB1 or SMB2 marker
	if ( ! HasSMBHeader(data) )
		{
		NeedResync();
		return false;
		}

	resync_state = INSYNC;
	first_time = last_time = 0.0;
	msg_len = 0;
	msg_type = 0;
	return true;
	}

void Contents_SMB::DeliverStream(int len, const u_char* data, bool orig)
	{
	TCP_SupportAnalyzer::DeliverStream(len, data, orig);
	
	if (!CheckResync(len, data, orig))
		return;   // Not in sync yet. Still resyncing

	while ( len > 0 )
		{
		switch (state) {
		case WAIT_FOR_HDR:
			{
			// We have the 4 bytes header now

			// This does not abide the spec, but we've seen it 
			// in real traffic.
			if (data[1] > 2)
				Conn()->Weird(fmt("NetBIOS session flags > 2: %d", data[1]));
			msg_len = 0;
			msg_type = data[0];
			for ( int i = 1; i < 4; i++)
				msg_len = (msg_len << 8) + data[i];
			msg_len+=4;
			msg_buf.Init(SMB_MAX_LEN+4, msg_len);
			state = WAIT_FOR_DATA;
			}
			break;
		case WAIT_FOR_DATA:
			{
			bool got_all_data = msg_buf.ConsumeChunk(data, len);
			if ( got_all_data )
				{
				const u_char *dummy_p = msg_buf.GetBuf();
				int dummy_len = (int) msg_buf.GetFill();
				DeliverSMB(dummy_len, dummy_p);
				
				state = WAIT_FOR_HDR;
				}
			}
			break;
		} // end switch
		} // end while
	}
