#
# The development of Zeek's Modbus analyzer has been made possible thanks to
# the support of the Ministry of Security and Justice of the Kingdom of the
# Netherlands within the projects of Hermes, Castor and Midas.
#
# Useful references: http://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf
#                    http://www.simplymodbus.ca/faq.htm

%include binpac.pac
%include zeek.pac

%extern{
#include "zeek/analyzer/protocol/modbus/events.bif.h"
%}

analyzer ModbusTCP withcontext {
	connection: ModbusTCP_Conn;
	flow:       ModbusTCP_Flow;
};

connection ModbusTCP_Conn(zeek_analyzer: ZeekAnalyzer) {
	upflow = ModbusTCP_Flow(true);
	downflow = ModbusTCP_Flow(false);
};

%include modbus-protocol.pac

flow ModbusTCP_Flow(is_orig: bool) {
	flowunit = ModbusTCP_PDU(is_orig) withcontext (connection, this);
}

%include modbus-analyzer.pac
