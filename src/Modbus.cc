#include "Modbus.h"
#include "TCP_Reassembler.h"

ModbusTCP_Analyzer::ModbusTCP_Analyzer(Connection* c)
: TCP_ApplicationAnalyzer(AnalyzerTag::Modbus, c)
	{
	interp = new binpac::ModbusTCP::ModbusTCP_Conn(this);
	}

ModbusTCP_Analyzer::~ModbusTCP_Analyzer()
	{
	delete interp;
	}

void ModbusTCP_Analyzer::Done()
	{
	TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void ModbusTCP_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);
	interp->NewData(orig, data, data + len);
	}

void ModbusTCP_Analyzer::Undelivered(int seq, int len, bool orig)
	{
	}

void ModbusTCP_Analyzer::EndpointEOF(TCP_Reassembler* endp)
	{
	TCP_ApplicationAnalyzer::EndpointEOF(endp);
	interp->FlowEOF(endp->IsOrig());
	}

