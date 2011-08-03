// See the file "COPYING" in the main distribution directory for copyright.

#ifndef tunnelhandler_h
#define tunnelhandler_h

#include "IP.h"
#include "Conn.h"
#include "Sessions.h"
#include "Val.h"


class TunnelInfo {
public:
	TunnelInfo()
		{
		child = 0;
		tunneltype = BifEnum::NONE;
		hdr_len = 0;
		parent.src_addr = parent.dst_addr = 0;
		parent.src_port = parent.dst_port = 0;
		parent.is_one_way = 0;
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
	void SetParentPorts(uint32 src_port, uint32 dst_port)
		{
		parent.src_port = src_port;
		parent.dst_port = dst_port;
		}

	RecordVal* GetRecordVal() const 
		{
		RecordVal *rv = new RecordVal(BifType::Record::tunnel_parent_t);

		RecordVal* id_val = new RecordVal(conn_id);
		id_val->Assign(0, new AddrVal(parent.src_addr));
		id_val->Assign(1, new PortVal(ntohs(parent.src_port), TRANSPORT_UNKNOWN));
		id_val->Assign(2, new AddrVal(parent.dst_addr));
		id_val->Assign(3, new PortVal(ntohs(parent.dst_port), TRANSPORT_UNKNOWN));
		rv->Assign(0, id_val);
		rv->Assign(1, new EnumVal(tunneltype, BifType::Enum::tunneltype_t));
		return rv;
		}

	IP_Hdr *child;
	ConnID parent;
	int hdr_len;
	BifEnum::tunneltype_t tunneltype;
};

class TunnelHandler {
public:
	TunnelHandler(NetSessions *arg_s);
	~TunnelHandler();

	TunnelInfo* DecapsulateTunnel(const IP_Hdr* ip_hdr, int len, int caplen,
			/* need those for passing them back to NetSessions::Weird() */
			const struct pcap_pkthdr* hdr, const u_char* const pkt);

protected:
	NetSessions *s;
};


#endif
