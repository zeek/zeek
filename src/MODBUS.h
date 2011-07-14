
#ifndef modbus_h
#define modbus_h

#include "TCP.h"

#include "modbus_pac.h"

class Modbus_Analyzer : public TCP_ApplicationAnalyzer {
public:
        Modbus_Analyzer(Connection* conn);
        virtual ~Modbus_Analyzer();

        virtual void Done();
        virtual void DeliverStream(int len, const u_char* data, bool orig);
        virtual void Undelivered(int seq, int len, bool orig);

        static Analyzer* InstantiateAnalyzer(Connection* conn)
                { return new Modbus_Analyzer(conn); }

        // Put event names in this function
        static bool Available()
                { return 
		modbus_request || modbus_header || modbus_request_read_multiple_register || 
		modbus_request_write_multiple_register || modbus_register_unit ||
		modbus_request_read_coil || modbus_request_read_input_discrete || 
		modbus_request_read_input_register || modbus_request_write_coil ||
		modbus_request_write_single_register || modbus_request_read_exception_status ||
		modbus_request_force_multiple_coils || modbus_request_read_general_reference ||
		modbus_request_write_general_reference || modbus_reference ||
		modbus_reference_with_data || modbus_register_value_unit || 
		modbus_request_mask_write_register || modbus_request_read_write_registers ||
		modbus_request_read_FIFO_queue ||
		modbus_response || modbus_response_read_multiple_register ||
		modbus_response_write_multiple_register || modbus_rregister_unit ||
		modbus_response_read_coil || modbus_response_read_input_discrete ||
		modbus_response_read_input_register || modbus_response_write_coil ||
		modbus_response_write_single_register || modbus_response_read_exception_status ||
		modbus_response_force_multiple_coils || modbus_response_read_general_reference ||
		modbus_response_write_general_reference || modbus_response_mask_write_register ||
		modbus_response_read_write_registers || modbus_response_read_FIFO_queue ||
		modbus_rregister_data_unit || modbus_exception; 
		}

protected:
        binpac::ModbusTCP::ModbusTCP_Conn* interp;
};

#endif

