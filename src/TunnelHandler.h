// See the file "COPYING" in the main distribution directory for copyright.

#ifndef tunnelhandler_h
#define tunnelhandler_h

#include <netinet/udp.h>
#include "net_util.h"
#include "IP.h"
#include "IPAddr.h"
#include "Conn.h"
#include "Sessions.h"
#include "Val.h"

class TunnelParent {
public:
	TunnelParent()
		{
		tunneltype = BifEnum::Tunnel::NONE;
		src_port = dst_port = 0;
		}

	TunnelParent(TunnelParent *other)
		{
		tunneltype = other->tunneltype;
		src_addr = other->src_addr;
		dst_addr = other->dst_addr;
		src_port = other->src_port;
		dst_port = other->dst_port;
		}

	RecordVal* GetRecordVal() const 
		{
		RecordVal *rv = new RecordVal(BifType::Record::Tunnel::Parent);
		TransportProto tproto;
		switch ( tunneltype ) {
		case BifEnum::Tunnel::IP6_IN_IP:
		case BifEnum::Tunnel::IP4_IN_IP:
			tproto = TRANSPORT_UNKNOWN;
			break;
		default:
			tproto = TRANSPORT_UDP;
		} // end switch

		RecordVal* id_val = new RecordVal(conn_id);
		id_val->Assign(0, new AddrVal(src_addr));
		id_val->Assign(1, new PortVal(ntohs(src_port), tproto));
		id_val->Assign(2, new AddrVal(dst_addr));
		id_val->Assign(3, new PortVal(ntohs(dst_port), tproto));
		rv->Assign(0, id_val);
		rv->Assign(1, new EnumVal(tunneltype, BifType::Enum::Tunnel::Tunneltype));
		return rv;
		}

	IPAddr src_addr;
	IPAddr dst_addr;
	uint16 src_port;
	uint16 dst_port;
	BifEnum::Tunnel::Tunneltype tunneltype;
};

class TunnelInfo {
public:
	TunnelInfo()
		{
		child = 0;
		hdr_len = 0;
		}
	~TunnelInfo() 
		{
		if (child) delete child;
		}

	void SetParentIPs(const IP_Hdr *ip_hdr)
		{
		parent.src_addr = ip_hdr->SrcAddr();
		parent.dst_addr = ip_hdr->DstAddr();
		}
	void SetParentPorts(const struct udphdr *uh)
		{
		parent.src_port = uh->uh_sport;
		parent.dst_port = uh->uh_dport;
		}

	IP_Hdr *child;
	TunnelParent parent;
	int hdr_len;
};

class TunnelHandler {
public:
	TunnelHandler(NetSessions *arg_s);
	~TunnelHandler();

	// Main entry point. Returns a nil if not tunneled.
	TunnelInfo* DecapsulateTunnel(const IP_Hdr* ip_hdr, int len, int caplen,
			// need those for passing them back to NetSessions::Weird() 
			const struct pcap_pkthdr* hdr, const u_char* const pkt);

protected:
	NetSessions *s;
	short udp_ports[65536]; // which UDP ports to decapsulate
	IP_Hdr* LookForIPHdr(const u_char *data, int datalen);
	TunnelInfo* HandleUDP(const IP_Hdr *ip_hdr, int len, int caplen);
};


#endif
