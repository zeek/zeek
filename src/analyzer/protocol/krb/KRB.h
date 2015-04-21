// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_KRB_KRB_H
#define ANALYZER_PROTOCOL_KRB_KRB_H

#include "krb_pac.h"

namespace analyzer { namespace krb {

class KRB_Analyzer : public analyzer::Analyzer {

public:
	KRB_Analyzer(Connection* conn);
	virtual ~KRB_Analyzer();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
							   uint64 seq, const IP_Hdr* ip, int caplen);

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new KRB_Analyzer(conn); }

protected:

	binpac::KRB::KRB_Conn* interp;
};

} } // namespace analyzer::*

#endif
