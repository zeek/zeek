// $Id: UDP.h 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef udp_h
#define udp_h

#include "Analyzer.h"
#include "Rewriter.h"

class UDP_Rewriter;

typedef enum {
	UDP_INACTIVE,	// no packet seen
	UDP_ACTIVE,	// packets seen
} UDP_EndpointState;

class UDP_Analyzer : public TransportLayerAnalyzer {
public:
	UDP_Analyzer(Connection* conn);
	virtual ~UDP_Analyzer();

	virtual void Init();

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new UDP_Analyzer(conn); }

	static bool Available() { return true; }

	// -- XXX -- only want to return yes if the protocol flag is
	//  on similar to TCP. (e.g. FTP_Connection etc.) /mc
	int RewritingTrace() const	{ return 0; }

protected:
	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen);
	virtual void UpdateEndpointVal(RecordVal* endp, int is_orig);
	virtual bool IsReuse(double t, const u_char* pkt);
	virtual unsigned int MemoryAllocation() const;

	bro_int_t request_len, reply_len;

#define HIST_ORIG_DATA_PKT 0x1
#define HIST_RESP_DATA_PKT 0x2
#define HIST_ORIG_CORRUPT_PKT 0x4
#define HIST_RESP_CORRUPT_PKT 0x8
};

#endif
