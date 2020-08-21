#pragma once

#include "analyzer/protocol/tcp/TCP.h"
#include "modbus_pac.h"

namespace zeek::analyzer::modbus {

class ModbusTCP_Analyzer : public zeek::analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	explicit ModbusTCP_Analyzer(zeek::Connection* conn);
	~ModbusTCP_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;

	void Undelivered(uint64_t seq, int len, bool orig) override;
	void EndpointEOF(bool is_orig) override;

	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{ return new ModbusTCP_Analyzer(conn); }

protected:
	binpac::ModbusTCP::ModbusTCP_Conn* interp;
};

} // namespace zeek::analyzer::modbus

namespace analyzer::modbus {

using ModbusTCP_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::modbus::ModbusTCP_Analyzer.")]] = zeek::analyzer::modbus::ModbusTCP_Analyzer;

} // namespace analyzer::modbus
