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

/**
 * Analyzes security data of ADAT exchanges over FTP control session (RFC 2228).
 * Currently only the GSI mechanism of GSSAPI AUTH method is understood.
 * The ADAT exchange for GSI is base64 encoded TLS/SSL handshake tokens.  This
 * analyzer just decodes the tokens and passes them on to the parent, which must
 * be an SSL analyzer instance.
 */
class FTP_ADAT_Analyzer : public SupportAnalyzer {
public:
	FTP_ADAT_Analyzer(Connection* conn, bool arg_orig)
	    : SupportAnalyzer(AnalyzerTag::FTP_ADAT, conn, arg_orig),
	      first_token(true) { }

	void DeliverStream(int len, const u_char* data, bool orig);

protected:
	// Used by the client-side analyzer to tell if it needs to peek at the
	// initial context token and do sanity checking (i.e. does it look like
	// a TLS/SSL handshake token).
	bool first_token;
};

#endif
