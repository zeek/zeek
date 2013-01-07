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

	static Analyzer* InstantiateAnalyzer(Connection* conn, const AnalyzerTag& tag)
		{ return new ModbusTCP_Analyzer(conn); }

	// Put event names in this function
	static bool Available(const AnalyzerTag& tag)
		{
		return modbus_message
		     | modbus_exception
		     | modbus_read_coils_request
		     | modbus_read_coils_response
		     | modbus_read_discrete_inputs_request
		     | modbus_read_discrete_inputs_response
		     | modbus_read_holding_registers_request
		     | modbus_read_holding_registers_response
		     | modbus_read_input_registers_request
		     | modbus_read_input_registers_response
		     | modbus_write_single_coil_request
		     | modbus_write_single_coil_response
		     | modbus_write_single_register_request
		     | modbus_write_single_register_response
		     | modbus_write_multiple_coils_request
		     | modbus_write_multiple_coils_response
		     | modbus_write_multiple_registers_request
		     | modbus_write_multiple_registers_response
		     | modbus_read_file_record_request
		     | modbus_read_file_record_response
		     | modbus_write_file_record_request
		     | modbus_write_file_record_response
		     | modbus_mask_write_register_request
		     | modbus_mask_write_register_response
		     | modbus_read_write_multiple_registers_request
		     | modbus_read_write_multiple_registers_response
		     | modbus_read_fifo_queue_request
		     | modbus_read_fifo_queue_response;
		}

protected:
	binpac::ModbusTCP::ModbusTCP_Conn* interp;
};

#endif
