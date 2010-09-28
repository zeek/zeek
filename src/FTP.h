// $Id: FTP.h 6782 2009-06-28 02:19:03Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ftp_h
#define ftp_h

#include "NVT.h"
#include "TCP.h"

class FTP_Analyzer : public TCP_ApplicationAnalyzer {
public:
	FTP_Analyzer(Connection* conn);

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual int RewritingTrace()
		{
		return rewriting_ftp_trace ||
			TCP_ApplicationAnalyzer::RewritingTrace();
		}

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{
		return new FTP_Analyzer(conn);
		}

	static bool Available()	{ return ftp_request || ftp_reply; }


protected:
	FTP_Analyzer()	{}

	NVT_Analyzer* nvt_orig;
	NVT_Analyzer* nvt_resp;
	uint32 pending_reply;	// code associated with multi-line reply, or 0
	string auth_requested;	// AUTH method requested
};

#endif
