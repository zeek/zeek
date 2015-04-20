// See the file "COPYING" in the main distribution directory for copyright.
//
// See ConnSize.h for more extensive comments.


#include "ConnSize.h"
#include "analyzer/protocol/tcp/TCP.h"

#include "events.bif.h"

using namespace analyzer::conn_size;

ConnSize_Analyzer::ConnSize_Analyzer(Connection* c)
    : Analyzer("CONNSIZE", c),
      orig_bytes(), resp_bytes(), orig_pkts(), resp_pkts()
	{
	}


ConnSize_Analyzer::~ConnSize_Analyzer()
	{
	}

void ConnSize_Analyzer::Init()
	{
	Analyzer::Init();

	orig_bytes = 0;
	orig_pkts = 0;
	resp_bytes = 0;
	resp_pkts = 0;

	orig_bytes_thresh = 0;
	orig_pkts_thresh = 0;
	resp_bytes_thresh = 0;
	resp_pkts_thresh = 0;
	}

void ConnSize_Analyzer::Done()
	{
	Analyzer::Done();
	}

void ConnSize_Analyzer::ThresholdEvent(EventHandlerPtr f, uint64 threshold, bool is_orig)
	{
	if ( ! f )
		return;

	val_list* vl = new val_list;
	vl->append(BuildConnVal());
	vl->append(new Val(threshold, TYPE_COUNT));
	vl->append(new Val(is_orig, TYPE_BOOL));
	ConnectionEvent(f, vl);
	}

void ConnSize_Analyzer::CheckSizes(bool is_orig)
	{
	if ( is_orig )
		{
		if ( orig_bytes_thresh && orig_bytes >= orig_bytes_thresh )
			{
			ThresholdEvent(conn_bytes_threshold_crossed, orig_bytes_thresh, is_orig);
			orig_bytes_thresh = 0;
			}

		if ( orig_pkts_thresh && orig_pkts >= orig_pkts_thresh )
			{
			ThresholdEvent(conn_packets_threshold_crossed, orig_pkts_thresh, is_orig);
			orig_pkts_thresh = 0;
			}
		}
	else
		{
		if ( resp_bytes_thresh && resp_bytes >= resp_bytes_thresh )
			{
			ThresholdEvent(conn_bytes_threshold_crossed, resp_bytes_thresh, is_orig);
			resp_bytes_thresh = 0;
			}

		if ( resp_pkts_thresh && resp_pkts >= resp_pkts_thresh )
			{
			ThresholdEvent(conn_packets_threshold_crossed, resp_pkts_thresh, is_orig);
			resp_pkts_thresh = 0;
			}
		}
	}

void ConnSize_Analyzer::DeliverPacket(int len, const u_char* data, bool is_orig, uint64 seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, is_orig, seq, ip, caplen);

	if ( is_orig )
		{
		orig_bytes += ip->TotalLen();
		orig_pkts ++;
		}
	else
		{
		resp_bytes += ip->TotalLen();
		resp_pkts ++;
		}

	CheckSizes(is_orig);
	}

void ConnSize_Analyzer::SetThreshold(uint64 threshold, bool bytes, bool orig)
	{
	if ( bytes )
		{
		if ( orig )
			orig_bytes_thresh = threshold;
		else
			resp_bytes_thresh = threshold;
		}
	else
		{
		if ( orig )
			orig_pkts_thresh = threshold;
		else
			resp_pkts_thresh = threshold;
		}

	// Check if threshold is already crossed.
	CheckSizes(orig);
	}

uint64_t ConnSize_Analyzer::GetThreshold(bool bytes, bool orig)
	{
	if ( bytes )
		{
		if ( orig )
			return orig_bytes_thresh;
		else
			return resp_bytes_thresh;
		}
	else
		{
		if ( orig )
			return orig_pkts_thresh;
		else
			return resp_pkts_thresh;
		}
	}

void ConnSize_Analyzer::UpdateConnVal(RecordVal *conn_val)
	{
	// RecordType *connection_type is decleared in NetVar.h
	RecordVal *orig_endp = conn_val->Lookup("orig")->AsRecordVal();
	RecordVal *resp_endp = conn_val->Lookup("resp")->AsRecordVal();

	// endpoint is the RecordType from NetVar.h
	int pktidx = endpoint->FieldOffset("num_pkts");
	int bytesidx = endpoint->FieldOffset("num_bytes_ip");

	if ( pktidx < 0 )
		reporter->InternalError("'endpoint' record missing 'num_pkts' field");

	if ( bytesidx < 0 )
		reporter->InternalError("'endpoint' record missing 'num_bytes_ip' field");

	orig_endp->Assign(pktidx, new Val(orig_pkts, TYPE_COUNT));
	orig_endp->Assign(bytesidx, new Val(orig_bytes, TYPE_COUNT));
	resp_endp->Assign(pktidx, new Val(resp_pkts, TYPE_COUNT));
	resp_endp->Assign(bytesidx, new Val(resp_bytes, TYPE_COUNT));

	Analyzer::UpdateConnVal(conn_val);
	}


void ConnSize_Analyzer::FlipRoles()
	{
	Analyzer::FlipRoles();
	uint64_t tmp;

	tmp = orig_bytes;
	orig_bytes = resp_bytes;
	resp_bytes = tmp;

	tmp = orig_pkts;
	orig_pkts = resp_pkts;
	resp_pkts = tmp;
	}

