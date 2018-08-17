// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_KRB_KRB_H
#define ANALYZER_PROTOCOL_KRB_KRB_H

#include "krb_pac.h"

#ifdef USE_KRB5
#include <krb5.h>
#endif

namespace analyzer { namespace krb {

class KRB_Analyzer : public analyzer::Analyzer {

public:
	explicit KRB_Analyzer(Connection* conn);
	virtual ~KRB_Analyzer();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
							   uint64 seq, const IP_Hdr* ip, int caplen);

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new KRB_Analyzer(conn); }

	StringVal* GetAuthenticationInfo(const BroString* principal, const BroString* ciphertext, const bro_uint_t enctype);

protected:

	binpac::KRB::KRB_Conn* interp;

private:
	static bool krb_available;
#ifdef USE_KRB5
	static std::once_flag krb_initialized;
	static void Initialize_Krb();
	static krb5_context krb_context;
	static krb5_keytab krb_keytab;
#endif
};

} } // namespace analyzer::*

#endif
