#include "IP.h"
#include "PacketSort.h"

const bool DEBUG_packetsort = false;

PacketSortElement::PacketSortElement(PktSrc* arg_src,
			double arg_timestamp, const struct pcap_pkthdr* arg_hdr,
			const u_char* arg_pkt, int arg_hdr_size)
	{
	src = arg_src;
	timestamp = arg_timestamp;
	hdr = *arg_hdr;
	hdr_size = arg_hdr_size;

	pkt = new u_char[hdr.caplen];
	memcpy(pkt, arg_pkt, hdr.caplen);

	is_tcp = 0;
	ip_hdr = 0;
	tcp_flags = 0;
	endp = 0;
	payload_length = 0;
	key = 0;

	// Now check if it is a "parsable" TCP packet.
	uint32 caplen = hdr.caplen;
	uint32 tcp_offset;

	if ( caplen >= sizeof(struct ip) + hdr_size )
		{
		const struct ip* ip = (const struct ip*) (pkt + hdr_size);
		if ( ip->ip_v == 4 )
			ip_hdr = new IP_Hdr(ip, false);
		else if ( ip->ip_v == 6 && (caplen >= sizeof(struct ip6_hdr) + hdr_size) )
			ip_hdr = new IP_Hdr((const struct ip6_hdr*) ip, false, caplen - hdr_size);
		else
			// Weird will be generated later in NetSessions::NextPacket.
			return;

		if ( ip_hdr->NextProto() == IPPROTO_TCP &&
		      // Note: can't sort fragmented packets
		     ( ! ip_hdr->IsFragment() ) )
			{
			tcp_offset = hdr_size + ip_hdr->HdrLen();
			if ( caplen >= tcp_offset + sizeof(struct tcphdr) )
				{
				const struct tcphdr* tp = (const struct tcphdr*)
							(pkt + tcp_offset);

				id.src_addr = ip_hdr->SrcAddr();
				id.dst_addr = ip_hdr->DstAddr();
				id.src_port = tp->th_sport;
				id.dst_port = tp->th_dport;
				id.is_one_way = 0;

				endp = addr_port_canon_lt(id.src_addr,
							  id.src_port,
							  id.dst_addr,
							  id.dst_port) ? 0 : 1;

				seq[endp] = ntohl(tp->th_seq);

				if ( tp->th_flags & TH_ACK )
					seq[1-endp] = ntohl(tp->th_ack);
				else
					seq[1-endp] = 0;

				tcp_flags = tp->th_flags;

				// DEBUG_MSG("%.6f: %u, %u\n", timestamp, seq[0], seq[1]);

				payload_length = ip_hdr->PayloadLen() - tp->th_off * 4;

				key = BuildConnIDHashKey(id);

				is_tcp = 1;
				}
			}
		}

	if ( DEBUG_packetsort && ! is_tcp )
		DEBUG_MSG("%.6f non-TCP packet\n", timestamp);
	}

PacketSortElement::~PacketSortElement()
	{
	delete [] pkt;
	delete ip_hdr;
	delete key;
	}

int PacketSortPQ::Timestamp_Cmp(PacketSortElement* a, PacketSortElement* b)
	{
	double d = a->timestamp - b->timestamp;

	if ( d > 0 ) return 1;
	else if ( d < 0 ) return -1;
	else return 0;
	}

int PacketSortPQ::UpdatePQ(PacketSortElement* prev_e, PacketSortElement* new_e)
	{
	int index = prev_e->pq_index[pq_level];

	new_e->pq_index[pq_level] = index;
	pq[index] = new_e;

	if ( Cmp(prev_e, new_e) > 0 )
		return FixUp(new_e, index);
	else
		{
		FixDown(new_e, index);
		return index == 0;
		}
	}

int PacketSortPQ::AddToPQ(PacketSortElement* new_e)
	{
	int index = pq.size();

	new_e->pq_index[pq_level] = index;
	pq.push_back(new_e);

	return FixUp(new_e, index);
	}

int PacketSortPQ::RemoveFromPQ(PacketSortElement* prev_e)
	{
	if ( pq.size() > 1 )
		{
		PacketSortElement* new_e = pq[pq.size() - 1];
		pq.pop_back();
		return UpdatePQ(prev_e, new_e);		
		}
	else
		{
		pq.pop_back();
		return 1;
		}
	}

void PacketSortPQ::Assign(int k, PacketSortElement* e)
	{
	pq[k] = e;
	e->pq_index[pq_level] = k;
	}

PacketSortConnPQ::~PacketSortConnPQ()
	{
	// Delete elements only in ConnPQ (not in GlobalPQ) to avoid
	// double delete.
	for ( int i = 0; i < (int) pq.size(); ++i )
		{
		delete pq[i];
		pq[i] = 0;
		}
	}

int PacketSortConnPQ::Cmp(PacketSortElement* a, PacketSortElement* b)
	{
	// Note: here we do not distinguish between packets without
	// an ACK and packets with seq/ack of 0. The later will sorted
	// only by their timestamps.

	if ( a->seq[0] && b->seq[0] && a->seq[0] != b->seq[0] )
		return (a->seq[0] > b->seq[0]) ? 1 : -1;

	else if ( a->seq[1] && b->seq[1] && a->seq[1] != b->seq[1] )
		return (a->seq[1] > b->seq[1]) ? 1 : -1;

	else
		return Timestamp_Cmp(a, b);
	}

int PacketSortPQ::FixUp(PacketSortElement* e, int k)
	{
	if ( k == 0 )
		{
		Assign(0, e);
		return 1;
		}

	int parent = (k-1) / 2;
	if ( Cmp(pq[parent], e) > 0 )
		{
		Assign(k, pq[parent]);
		return FixUp(e, parent);
		}
	else
		{
		Assign(k, e);
		return 0;
		}
	}

void PacketSortPQ::FixDown(PacketSortElement* e, int k)
	{
	uint32 kid = k * 2 + 1;

	if ( kid >= pq.size() )
		{
		Assign(k, e);
		return;
		}

	if ( kid + 1 < pq.size() && Cmp(pq[kid], pq[kid+1]) > 0 )
		++kid;

	if ( Cmp(e, pq[kid]) > 0 )
		{
		Assign(k, pq[kid]);
		FixDown(e, kid);
		}
	else
		Assign(k, e);
	}


int PacketSortConnPQ::Add(PacketSortElement* e)
	{
#if 0
	int endp = e->endp;
	uint32 end_seq = e->seq[endp] + e->payload_length;

	int p = 1 - endp;
	if ( (e->tcp_flags & TH_RST) && ! (e->tcp_flags & TH_ACK) )
		{
		DEBUG_MSG("%.6f %c: %u -> %u\n",
			  e->TimeStamp(), (p == endp) ? 'S' : 'A',
			  e->seq[p], next_seq[p]);
		e->seq[p] = next_seq[p];
		}

	if ( end_seq > next_seq[endp] )
		next_seq[endp] = end_seq;
#endif

	return AddToPQ(e);
	}

void PacketSortConnPQ::UpdateDeliveredSeq(int endp, int seq, int len, int ack)
	{
	if ( delivered_seq[endp] == 0 || delivered_seq[endp] == seq )
		delivered_seq[endp] = seq + len;
	if ( ack > delivered_seq[1 - endp] )
		delivered_seq[endp] = ack;
	}

bool PacketSortConnPQ::IsContentGapSafe(PacketSortElement* e)
	{
	int ack = e->seq[1 - e->endp];
	return ack <= delivered_seq[1 - e->endp];
	}

int PacketSortConnPQ::Remove(PacketSortElement* e)
	{
	int ret = RemoveFromPQ(e);
	UpdateDeliveredSeq(e->endp, e->seq[e->endp], e->payload_length,
				e->seq[1 - e->endp]);
	return ret;
	}

static void DeleteConnPQ(void* p)
	{
	delete (PacketSortConnPQ*) p;
	}

PacketSortGlobalPQ::PacketSortGlobalPQ()
	{
	pq_level = GLOBAL_PQ;
	conn_pq_table.SetDeleteFunc(DeleteConnPQ);
	}

PacketSortGlobalPQ::~PacketSortGlobalPQ()
	{
	// Destruction of PacketSortConnPQ will delete all conn_pq's.
	}

int PacketSortGlobalPQ::Add(PacketSortElement* e)
	{
	if ( e->is_tcp )
		{
		// TCP packets are sorted by sequence numbers
		PacketSortConnPQ* conn_pq = FindConnPQ(e);
		PacketSortElement* prev_min = conn_pq->Min();

		if ( conn_pq->Add(e) )
			{
			ASSERT(conn_pq->Min() != prev_min);

			if ( prev_min )
				return UpdatePQ(prev_min, e);
			else
				return AddToPQ(e);
			}

		else
			{
			ASSERT(conn_pq->Min() == prev_min);
			return 0;
			}
		}
	else
		return AddToPQ(e);
	}

PacketSortElement* PacketSortGlobalPQ::RemoveMin(double timestamp)
	{
	PacketSortElement* e = Min();

	if ( ! e )
		return 0;

	if ( e->is_tcp )
		{
		PacketSortConnPQ* conn_pq = FindConnPQ(e);

#if 0
		// Note: the content gap safety check does not work
		// because we remove the state for a connection once
		// it has no packet in the priority queue.

		// Do not deliver e if it arrives later than timestamp,
		// and is not content-gap-safe.
		if ( e->timestamp > timestamp &&
		     ! conn_pq->IsContentGapSafe(e) )
			return 0;
#else
		if ( e->timestamp > timestamp )
			return 0;
#endif

		conn_pq->Remove(e);
		PacketSortElement* new_e = conn_pq->Min();

		if ( new_e )
			UpdatePQ(e, new_e);
		else
			{
			RemoveFromPQ(e);
			conn_pq_table.Remove(e->key);
			delete conn_pq;
			}
		}
	else
		RemoveFromPQ(e);

	return e;
	}

PacketSortConnPQ* PacketSortGlobalPQ::FindConnPQ(PacketSortElement* e)
	{
	if ( ! e->is_tcp )
		reporter->InternalError("cannot find a connection for an invalid id");

	PacketSortConnPQ* pq = (PacketSortConnPQ*) conn_pq_table.Lookup(e->key);
	if ( ! pq )
		{
		pq = new PacketSortConnPQ();
		conn_pq_table.Insert(e->key, pq);
		}

	return pq;
	}
