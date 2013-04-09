#ifndef MODBUS_H
#define MODBUS_H

#include "TCP.h"
#include "modbus_pac.h"

class ModbusTCP_Analyzer : public TCP_ApplicationAnalyzer {
public:
	ModbusTCP_Analyzer(Connection* conn);
	virtual ~ModbusTCP_Analyzer();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);

	virtual void Undelivered(int seq, int len, bool orig);
	virtual void EndpointEOF(bool is_orig);

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new ModbusTCP_Analyzer(conn); }

protected:
	binpac::ModbusTCP::ModbusTCP_Conn* interp;
};

#endif
