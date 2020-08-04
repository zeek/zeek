// See the file "COPYING" in the main distribution directory for copyright.

#include "SNMP.h"
#include "Func.h"
#include "Reporter.h"
#include "types.bif.h"
#include "events.bif.h"

namespace zeek::analyzer::snmp {

SNMP_Analyzer::SNMP_Analyzer(zeek::Connection* conn)
	: Analyzer("SNMP", conn)
	{
	interp = new binpac::SNMP::SNMP_Conn(this);
	}

SNMP_Analyzer::~SNMP_Analyzer()
	{
	delete interp;
	}

void SNMP_Analyzer::Done()
	{
	Analyzer::Done();
	Event(udp_session_done);
	}

void SNMP_Analyzer::DeliverPacket(int len, const u_char* data, bool orig,
                                  uint64_t seq, const zeek::IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}

} // namespace zeek::analyzer::snmp
