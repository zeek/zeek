// See the file "COPYING" in the main distribution directory for copyright.
//

#ifndef ANALYZER_PROTOCOL_CONN_SIZE_CONNSIZE_H
#define ANALYZER_PROTOCOL_CONN_SIZE_CONNSIZE_H

#include "analyzer/Analyzer.h"
#include "NetVar.h"

namespace analyzer { namespace conn_size {

class ConnSize_Analyzer : public analyzer::Analyzer {
public:
	ConnSize_Analyzer(Connection* c);
	virtual ~ConnSize_Analyzer();

	virtual void Init();
	virtual void Done();

	// from Analyzer.h
	virtual void UpdateConnVal(RecordVal *conn_val);
	virtual void FlipRoles();

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new ConnSize_Analyzer(conn); }

protected:
	virtual void DeliverPacket(int len, const u_char* data, bool is_orig,
					int seq, const IP_Hdr* ip, int caplen);


	uint64_t orig_bytes;
	uint64_t resp_bytes;
	uint64_t orig_pkts;
	uint64_t resp_pkts;
};

} } // namespace analyzer::* 

#endif
