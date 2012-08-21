
#ifndef modbus_h
#define modbus_h


#include "TCP.h"

#include "modbus_pac.h"

class ModbusTCP_Analyzer : public TCP_ApplicationAnalyzer {
public:
	ModbusTCP_Analyzer(Connection* conn);
	virtual ~ModbusTCP_Analyzer();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);

	virtual void Undelivered(int seq, int len, bool orig);
	virtual void EndpointEOF(TCP_Reassembler* endp);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new ModbusTCP_Analyzer(conn); }

	// Put event names in this function
	static bool Available()
		{ return 
		modbus_read_coils_request
                || modbus_read_coils_response
  		
		|| modbus_read_input_discretes_request
                || modbus_read_input_discretes_response		

		|| modbus_read_multi_request
		|| modbus_read_multi_response

		|| modbus_read_input_request
		|| modbus_read_input_response

		|| modbus_write_single_request
		|| modbus_write_single_response
		
		|| modbus_write_coil_request
		|| modbus_write_coil_response


		|| modbus_force_coils_request
                || modbus_force_coils_response

		|| modbus_write_multi_request
		|| modbus_write_multi_response

		|| modbus_mask_write_request
                || modbus_mask_write_response

		|| modbus_read_write_request
		|| modbus_read_write_response

		|| modbus_read_FIFO_request
                || modbus_read_FIFO_response

		|| modbus_read_except_request
		|| modbus_read_except_response

		|| modbus_exception
		|| modbus_request
                || modbus_response;

		}

protected:
	binpac::ModbusTCP::ModbusTCP_Conn* interp;
};

#endif
