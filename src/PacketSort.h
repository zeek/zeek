// $Id: PacketSort.h 3228 2006-06-08 02:12:03Z vern $

#ifndef packetsort_h
#define packetsort_h

// Timestamps can be imprecise and even inconsistent among packets
// from different sources. This class tries to guess a "correct"
// order by looking at TCP sequence numbers.
//
// In particular, it tries to eliminate "false" content gaps.

#include "Dict.h"
#include "Conn.h"

enum {
	CONN_PQ,
	GLOBAL_PQ,
	NUM_OF_PQ_LEVEL,
};

class PktSrc;

class PacketSortElement {
public:
	PacketSortElement(PktSrc* src, double timestamp,
				const struct pcap_pkthdr* hdr,
				const u_char* pkt, int hdr_size);
	~PacketSortElement();

	PktSrc* Src() const			{ return src; }
	double TimeStamp() const		{ return timestamp; }
	const struct pcap_pkthdr* Hdr() const	{ return &hdr; }
	const u_char* Pkt() const		{ return pkt; }
	int HdrSize() const			{ return hdr_size; }
	const IP_Hdr* IPHdr() const		{ return ip_hdr; }

protected:
	PktSrc* src;
	double timestamp;
	struct pcap_pkthdr hdr;
	u_char* pkt;
	int hdr_size;

	IP_Hdr* ip_hdr;
	int is_tcp;
	ConnID id;
	uint32 seq[2];	// indexed by endpoint
	int tcp_flags;
	int endp;	// 0 or 1
	int payload_length;

	HashKey* key;

	int pq_index[NUM_OF_PQ_LEVEL];

	friend class PacketSortPQ;
	friend class PacketSortConnPQ;
	friend class PacketSortGlobalPQ;
};

class PacketSortPQ {
public:
	PacketSortPQ()
		{ pq_level = -1; }
	virtual ~PacketSortPQ() {}

	PacketSortElement* Min() const	{ return (pq.size() > 0) ? pq[0] : 0; }

protected:
	virtual int Cmp(PacketSortElement* a, PacketSortElement* b) = 0;
	int Timestamp_Cmp(PacketSortElement* a, PacketSortElement* b);

	int UpdatePQ(PacketSortElement* prev_e, PacketSortElement* new_e);
	int AddToPQ(PacketSortElement* e);
	int RemoveFromPQ(PacketSortElement* e);

	void Assign(int k, PacketSortElement* e);
	int FixUp(PacketSortElement* e, int k);
	void FixDown(PacketSortElement* e, int k);

	vector<PacketSortElement*> pq;
	int pq_level;
};

// Sort by sequence numbers within a connection
class PacketSortConnPQ : public PacketSortPQ {
public:
	PacketSortConnPQ()
		{
		pq_level = CONN_PQ;
		delivered_seq[0] = delivered_seq[1] = 0;
		}
	~PacketSortConnPQ();

	int Add(PacketSortElement* e);

	int Remove(PacketSortElement* e);

	bool IsContentGapSafe(PacketSortElement* e);

protected:
	int Cmp(PacketSortElement* a, PacketSortElement* b);
	void UpdateDeliveredSeq(int endp, int seq, int len, int ack);

	int delivered_seq[2];
};

declare(PDict, PacketSortConnPQ);

// Sort by timestamps.
class PacketSortGlobalPQ : public PacketSortPQ {
public:
	PacketSortGlobalPQ();
	~PacketSortGlobalPQ();

	int Add(PacketSortElement* e);

	int Empty() const { return conn_pq_table.Length() == 0; }

	// Returns the next packet to dispatch if it arrives earlier than the
	// given timestamp, otherwise returns 0.
	// The packet, if to be returned, is also removed from the
	// priority queue.
	PacketSortElement* RemoveMin(double timestamp);

protected:
	int Cmp(PacketSortElement* a, PacketSortElement* b)
		{ return Timestamp_Cmp(a, b); }
	PacketSortConnPQ* FindConnPQ(PacketSortElement* e);

	PDict(PacketSortConnPQ) conn_pq_table;
};

#endif
