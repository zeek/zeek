// See the file "COPYING" in the main distribution directory for copyright.

#include "SNMP.h"
#include "Func.h"
#include "types.bif.h"
#include "events.bif.h"

using namespace analyzer::snmp;

SNMP_Analyzer::SNMP_Analyzer(Connection* conn)
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

void SNMP_Analyzer::DeliverPacket(uint64_t len, const u_char* data, bool orig,
                                  uint64_t seq, const IP_Hdr* ip, uint64_t caplen)
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
