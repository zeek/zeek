
#ifndef ANALYZER_PROTOCOL_DNP3_DNP3_H
#define ANALYZER_PROTOCOL_DNP3_DNP3_H

#include "analyzer/protocol/tcp/TCP.h"
#include "dnp3_pac.h"

namespace analyzer { namespace dnp3 {

class DNP3_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	DNP3_Analyzer(Connection* conn);
	virtual ~DNP3_Analyzer();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(int seq, int len, bool orig);
	virtual void EndpointEOF(bool is_orig);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new DNP3_Analyzer(conn); }

private:
	static const int MAX_BUFFER_SIZE = 300;

	struct Endpoint	{
		u_char buffer[MAX_BUFFER_SIZE];
		int buffer_len;
		bool in_hdr;
		int tpflags;
		int pkt_length;
		int pkt_cnt;
		bool encountered_first_chunk;
		};

	bool ProcessData(int len, const u_char* data, bool orig);
	void ClearEndpointState(bool orig);
	bool AddToBuffer(Endpoint* endp, int target_len, const u_char** data, int* len);
	bool ParseAppLayer(Endpoint* endp);
	bool CheckCRC(int len, const u_char* data, const u_char* crc16, const char* where);
	unsigned int CalcCRC(int len, const u_char* data);

	binpac::DNP3::DNP3_Conn* interp;

	Endpoint orig_state;
	Endpoint resp_state;

	static void PrecomputeCRCTable();

	static bool crc_table_initialized;
	static unsigned int crc_table[256];
};

} } // namespace analyzer::* 

#endif
