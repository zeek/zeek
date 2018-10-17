
#include "VXLAN.h"
#include "TunnelEncapsulation.h"
#include "Conn.h"
#include "IP.h"
#include "../arp/ARP.h"
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
		int eth_len = 14;
		int vxlan_len = 8;
		int eth_mac = 6;
		int proto = 0;
		reporter->Error("VXLANEncapsulation::DoParse len: %d", len);
		/* Note: outer Ethernet, IP, UDP layers already skipped */
		if ( len < vxlan_len )
		{
			Weird("VXLAN_truncated missing VXLAN header");
			return false;
		}
		/* Flags (8 bits): where the I flag MUST be set to 1 for a valid
			 VXLAN Network ID (VNI).  The other 7 bits (designated "R") are
			 reserved fields and MUST be set to zero on transmission and
			 ignored on receipt.*/
		if ( ! (data[0] & 0x8) )
		{
			Weird("VXLAN_flags packet missing I flag set ");
			return false;
		}
		if ( len < vxlan_len + eth_len )
		{
			Weird("VXLAN_truncated missing inner packet header");
			return false;
		}
		printf("Checking packet ethertype for inner packet:\n");
		uint16 proto_typ = ntohs(*((uint16*)(data+vxlan_len+2*eth_mac)));
		if ( proto_typ == 0x0800 )
			proto = IPPROTO_IPV4;
		else if ( proto_typ == 0x86dd )
			proto = IPPROTO_IPV6;
		else		{
			Weird("VXLAN_ethertype inner packet should be ethertype: IPv4 or IPv6");
			int i;
			for (i=0; i < 2; i++)
				printf("%02x ",data[vxlan_len+2*eth_mac+i]);
			return false;
		}
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
	reporter->Error("VXLANEncapsulation::BuildVal");

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
	int eth_len = 14;
	int udp_len = 8;
	int vlan_len = 4;
	int vxlan_len = 8;
	int eth_mac = 6;
	int i = 0;
	int vni= 0;
	int proto = 0;

	const EncapsulationStack* e = Conn()->GetEncapsulation();
	IP_Hdr* inner = 0;
	int rslt = sessions->ParseIPPacket(len, data + vxlan_len + eth_len, IPPROTO_IPV4, inner);

	reporter->Info("VXLAN_Analyzer::DeliverPacket");
	reporter->Info("len: %d", len);
	printf("Packet hex:\n");
	for (i=0; i < len; i++)
		printf("%0x ",data[i]);
	printf("\n");
	/* Note: outer Ethernet, IP, UDP layers already skipped */
	if ( len < vxlan_len )
	{
		Weird("VXLAN_truncated missing VXLAN header");
		return;
	}
	/* Flags (8 bits): where the I flag MUST be set to 1 for a valid
		 VXLAN Network ID (VNI).  The other 7 bits (designated "R") are
		 reserved fields and MUST be set to zero on transmission and
		 ignored on receipt.*/
	if ( ! (data[0] & 0x8) )
	{
		Weird("VXLAN_flags packet missing I flag set ");
		return;
	}
	if ( len < vxlan_len + eth_len )
	{
		Weird("VXLAN_truncated missing inner packet header");
		return;
	}
	printf("Checking packet ethertype for inner packet:\n");
	uint16 proto_typ = ntohs(*((uint16*)(data+vxlan_len+2*eth_mac)));
	switch (proto_typ)
	{
		case 0x0800:
			proto = IPPROTO_IPV4;
			break;
  	case 0x86dd:
			proto = IPPROTO_IPV6;
			break;
		case 0x8100:
		case 0x9100:
			/* 802.1q / 802.1ad */
			proto = proto_typ;
			if (len < vxlan_len + eth_len + vlan_len)
			{
				Weird("VXLAN truncated inner packet VLAN ether header ");
				return;
			}
      /* Set type then to next ethertype ? */
			break;
		default:
			Weird("VXLAN_ethertype inner packet should be ethertype: VLAN, IPv4 or IPv6");
			int i;
			for (i=0; i < 2; i++)
				printf("%02x ",data[vxlan_len+2*eth_mac+i]);
			return;

	}

	printf("Packet safety checks done\n");
	vni = (data[4] << 16) + (data[5] << 8) + (data[6] << 0);
	printf("VXLAN VNI %d\n",vni);

	/*	Do we want the inner packet with or without Ethernet header?
	data += vxlan_len + udp_len + eth_len;
	len -= vxlan_len + udp_len + eth_len;
	caplen -= vxlan_len + udp_len + eth_len;
*/
	data += udp_len + vxlan_len;
	len -= udp_len + vxlan_len;
	caplen -= udp_len + vxlan_len;
	EncapsulatingConn ec(Conn(), BifEnum::Tunnel::VXLAN);
	sessions->DoNextInnerPacket(network_time, 0, inner, e, ec);
  }
