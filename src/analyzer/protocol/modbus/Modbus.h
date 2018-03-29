#ifndef ANALYZER_PROTOCOL_MODBUS_MODBUS_H
#define ANALYZER_PROTOCOL_MODBUS_MODBUS_H

#include "analyzer/protocol/tcp/TCP.h"
#include "modbus_pac.h"

namespace analyzer { namespace modbus {

class ModbusTCP_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	explicit ModbusTCP_Analyzer(Connection* conn);
	~ModbusTCP_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;

	void Undelivered(uint64 seq, int len, bool orig) override;
	void EndpointEOF(bool is_orig) override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new ModbusTCP_Analyzer(conn); }

protected:
	binpac::ModbusTCP::ModbusTCP_Conn* interp;
};

} } // namespace analyzer::* 

#endif
