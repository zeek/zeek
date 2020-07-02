
#pragma once

#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/udp/UDP.h"

#include "dnp3_pac.h"

namespace analyzer { namespace dnp3 {

class DNP3_Base {
public:
	explicit DNP3_Base(zeek::analyzer::Analyzer* analyzer);
	virtual ~DNP3_Base();

	binpac::DNP3::DNP3_Conn* Interpreter()	{ return interp; }

protected:
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

	/**
	 * Buffers packet data until it reaches a specified length.
	 * @param endp an endpoint speaking DNP3 to which data will be buffered.
	 * @param target_len the required length of the buffer
	 * @param data source buffer to copy bytes from.  Will be incremented
	 * by the number of bytes copied by this function.
	 * @param len the number of bytes available in \a data.  Will be decremented
	 * by the number of bytes copied by this function.
	 * @return -1 if invalid input parameters were supplied, 0 if the endpoint's
	 * buffer is not yet \a target_len bytes in size, or 1 the buffer is the
	 * required size.
	 */
	int AddToBuffer(Endpoint* endp, int target_len, const u_char** data, int* len);

	bool ParseAppLayer(Endpoint* endp);
	bool CheckCRC(int len, const u_char* data, const u_char* crc16, const char* where);
	unsigned int CalcCRC(int len, const u_char* data);

	static void PrecomputeCRCTable();

	static bool crc_table_initialized;
	static unsigned int crc_table[256];

	zeek::analyzer::Analyzer* analyzer;
	binpac::DNP3::DNP3_Conn* interp;

	Endpoint orig_state;
	Endpoint resp_state;
};

class DNP3_TCP_Analyzer : public DNP3_Base, public tcp::TCP_ApplicationAnalyzer {
public:
	explicit DNP3_TCP_Analyzer(Connection* conn);
	~DNP3_TCP_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;
	void EndpointEOF(bool is_orig) override;

	static Analyzer* Instantiate(Connection* conn)
		{ return new DNP3_TCP_Analyzer(conn); }
};

class DNP3_UDP_Analyzer : public DNP3_Base, public zeek::analyzer::Analyzer {
public:
	explicit DNP3_UDP_Analyzer(Connection* conn);
	~DNP3_UDP_Analyzer() override;

	void DeliverPacket(int len, const u_char* data, bool orig,
                    uint64_t seq, const IP_Hdr* ip, int caplen) override;

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new DNP3_UDP_Analyzer(conn); }
};


} } // namespace analyzer::*
