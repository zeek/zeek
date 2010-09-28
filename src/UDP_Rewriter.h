// $Id:$
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef udp_rewriter_h
#define udp_rewriter_h

using namespace std;

#include <queue>
#include <set>

#include <pcap.h>

#include "Val.h"
#include "UDP.h"
#include "Anon.h"
#include "Rewriter.h"
#include "PacketDumper.h"

class UDP_TracePacket : public BroObj, virtual public TracePacket {
public:
	UDP_TracePacket(UDP_Rewriter* trace_rewriter, double t, int is_orig,
		    const struct pcap_pkthdr* hdr, int MTU, int initial_size);
	~UDP_TracePacket();

	int AppendLinkHeader(const u_char* chunk, int len);
	int AppendIPHeader(const u_char* chunk, int len);
	int AppendUDPHeader(const u_char* chunk, int len);
	int AppendData(const u_char* chunk, int len);

	void Reuse();
	int IsReuse() const	{ return reuse; }

	double TimeStamp() const	{ return timestamp; }
	int IsOrig() const	{ return is_orig; }

	const struct pcap_pkthdr* Header() const	{ return &pcap_hdr; }

	const u_char* Buffer() const	{ return pkt; }
	int Length() const	{ return buffer_offset; }

	// Note that Space() does not depend on buffer_size, but depends on MTU.
	int Space() const	{ return mtu - buffer_offset; }

	void Describe(ODesc* d) const	{ packet_val->Describe(d); }
	RecordVal* PacketVal();
	UDP_Rewriter* TraceRewriter() const	{ return trace_rewriter;}

	// has the packet been written to?
	int IsModified() const	{ return modified; }
	void SetModified()		{ modified = 1; }

	// BuildPacket() is called before dumping the packet. It sets length
	// fields and computes checksums in UDP/IP headers.
	int BuildPacket(struct pcap_pkthdr*& hdr, const u_char*& arg_pkt,
			int& length, ipaddr32_t anon_src, ipaddr32_t anon_dst);

private:
	int Append(const u_char* chunk, int len);

	RecordVal* packet_val;
	UDP_Rewriter* trace_rewriter;
	double timestamp;
	int packet_seq;
	int is_orig;
	struct pcap_pkthdr pcap_hdr;
	int mtu;
	u_char* pkt;	// of maximal length MTU
	int ip_offset, udp_offset, data_offset;
	int buffer_size;
	int buffer_offset;
	int reuse;	// whether it is an artificially replicated packet
	int on_hold;	// do not dump it in Flush()
	int seq_gap;
	int modified;
};

class UDP_Rewriter: public Rewriter {
public:
	UDP_Rewriter(Analyzer* analyzer, int arg_MTU, PacketDumper* dumper);

	virtual ~UDP_Rewriter();

	void Done();

	// these are the virt funcs in Rewriter....
	void WriteData(int is_orig, int len, const u_char* data);

	void WriteData(int is_orig, const char* data)
		{ WriteData(is_orig, strlen(data), data); }

	void WriteData(int is_orig, int len, const char* data)
		{ WriteData(is_orig, len, (const u_char*) data); }

	void WriteData(int is_orig, const BroString* str)
		{ WriteData(is_orig, str->Len(), str->Bytes()); }

	Analyzer* GetAnalyzer() const	{ return analyzer; }

	// Not need for udp, but declared in the virtual
	// and might be useful
	void Push(int);
	void AbortPackets(int);
	void CommitPackets(int);
	unsigned int ReserveSlot();
	int SeekSlot(unsigned int);
	int ReturnFromSlot();
	int ReleaseSlot(unsigned int);

	TracePacket* CurrentPacket() const	{ return current_packet; };
	TracePacket* RewritePacket() const	{ return next_packet; };

	// A UDP/IP packet.
	void NextPacket(int is_orig, double t,
			const struct pcap_pkthdr* pcap_hdr,
			const u_char* pcap_pkt,	// link level header
			int hdr_size,		// link level header size
			const struct ip* ip, const struct udphdr* tp);

	// Do not anonymize client/server IP address.
	int LeaveAddrInTheClear(int is_orig);

protected:
	void DoWriteData(int is_orig, int len, const u_char* data);

	Analyzer* analyzer;
	PacketDumper* dumper;

	int packets_rewritten;
	int MTU;
	ipaddr32_t anon_addr[2];

	UDP_TracePacket* current_packet;
	UDP_TracePacket* next_packet;
};

#endif
