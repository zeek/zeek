#include "MODBUS.h"
#include "TCP_Reassembler.h"

Modbus_Analyzer::Modbus_Analyzer(Connection* c)
: TCP_ApplicationAnalyzer(AnalyzerTag::ModbusTCP, c)
        {
        interp = new binpac::ModbusTCP::ModbusTCP_Conn(this);
        }

Modbus_Analyzer::~Modbus_Analyzer()
        {
        delete interp;
        }

void Modbus_Analyzer::Done()
        {
        Analyzer::Done();

        interp->FlowEOF(true);
        interp->FlowEOF(false);
        }

void Modbus_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
        {
        Analyzer::DeliverStream(len, data, orig);
        interp->NewData(orig, data, data + len);
        }

void Modbus_Analyzer::Undelivered(int seq, int len, bool orig)
        {
        }

