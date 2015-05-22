#ifndef l2_h
#define l2_h

#include "config.h"
#include "net_util.h"
#include "IP.h"
#include "Reporter.h"
#include "Val.h"
#include "Type.h"
#include "Packet.h"
#include <vector>

/**
 * A class that wraps an L2 packet.
 */
class L2_Hdr {
public:
	L2_Hdr(const Packet *arg_pkt)
		: pkt(arg_pkt)
		{
		}

	~L2_Hdr()
		{
		}

	/**
	 * Returns a raw_pkt_hdr RecordVal, which includes L2 and also
	 * everything in IP_Hdr (i.e. IP4/6 + tcp/udp/icmp)
	 */
	RecordVal* BuildPktHdrVal() const;

private:
	Val *fmt_eui48(const u_char *mac) const;
	const Packet *pkt;
};

#endif
