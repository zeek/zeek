
#include "VXLAN.h"
#include "TunnelEncapsulation.h"
#include "Conn.h"
#include "IP.h"
#include "Reporter.h"

#include "events.bif.h"

using namespace analyzer::vxlan;

void VXLAN_Analyzer::Done()
	{
	Analyzer::Done();
	Event(udp_session_done);
	}

bool VXLANEncapsulation::DoParse(const u_char* data, int& len)
	{
		unsigned int vxlan_len = 8;
		unsigned int eth_len = 14;
		if ( len < vxlan_len )
		{
			Weird("truncated_VXLAN");
			return false;
		}
		/* TODO Here we should check VXLAN flag I */
		/* And check for real packet inside, lets assume one for now */

		data += vxlan_len + eth_len;
		len -= vxlan_len + eth_len;
		inner_ip = data;
		return true;
	}

RecordVal* VXLANEncapsulation::BuildVal(const IP_Hdr* inner) const
	{
	static RecordType* vxlan_hdr_type = 0;
	static RecordType* vxlan_auth_type = 0;
	static RecordType* vxlan_origin_type = 0;

	RecordVal* vxlan_hdr = new RecordVal(vxlan_hdr_type);
	vxlan_hdr->Assign(1, inner->BuildPktHdrVal());
	return vxlan_hdr;
	}

void VXLAN_Analyzer::DeliverPacket(int len, const u_char* data, bool orig,
                                    uint64 seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);
	/* Note: it seems we get the packet AFTER UDP header. */

	VXLANEncapsulation vx(this);

	// If a carried packet has ethernet, this will help skip it.
	unsigned int eth_len = 14;
	unsigned int udp_len = 8;
	unsigned int vxlan_len = 8;

	const EncapsulationStack* e = Conn()->GetEncapsulation();
	IP_Hdr* inner = 0;
	int rslt = sessions->ParseIPPacket(len, data + vxlan_len + eth_len, IPPROTO_IPV4, inner);
/* TODO make a check for the Flags (8 bits): where the I flag MUST be set to 1 for a valid
			VXLAN Network ID (VNI).
		if ( flags_iflag & 0x0078 )
		{
		// Expect last 4 bits of flags are reserved, undefined.
		Weird("unknown_vxlan_flags", ip_hdr, encapsulation);
		return;
		}
*/
	if ( len < vxlan_len + udp_len || caplen < vxlan_len + udp_len )
		{
		Weird("truncated_VXLAN", ip);
		return;
		}

		/* Note: outer Ethernet and IP layers already skipped */
/*	Do we want the inner packet with or without Ethernet header?
	data += vxlan_len + udp_len + eth_len;
	len -= vxlan_len + udp_len + eth_len;
	caplen -= vxlan_len + udp_len + eth_len;
*/
	data += vxlan_len + udp_len;
	len -= vxlan_len + udp_len;
	caplen -= vxlan_len + udp_len;
	EncapsulatingConn ec(Conn(), BifEnum::Tunnel::VXLAN);
	sessions->DoNextInnerPacket(network_time, 0, inner, e, ec);
	}
