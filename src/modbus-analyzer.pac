

connection ModbusTCP_Conn(bro_analyzer: BroAnalyzer) {
    upflow = ModbusTCP_Flow(true);
    downflow = ModbusTCP_Flow(false);
};


#
# Flow
#
flow ModbusTCP_Flow(is_orig: bool) {
   	flowunit = ModbusTCP_PDU(is_orig) withcontext (connection, this);

        function get_modbus_request(length: uint16): bool
                %{
                if ( ::modbus_request )
                        {
                        BifEvent::generate_modbus_request(
                                connection()->bro_analyzer(),
                                connection()->bro_analyzer()->Conn(),
                                is_orig(), length);
                        }

                return true;
                %}

	# Hui Lin
	# ModbusTCP_TransportHeader
  	function get_modbus_header(tid: uint16, pid: uint16, len: uint16, uid: uint8, fc: uint8): bool
                %{
                if ( ::modbus_header )
                        {
                        BifEvent::generate_modbus_header(
                                connection()->bro_analyzer(),
                                connection()->bro_analyzer()->Conn(),
                                is_orig(), tid, pid, len, uid, fc);
                        }

                return true;
                %}

	# class 0
	# Hui Lin
	# ReadMultipleRegistersRequest
	function get_modbus_request_read_multiple_register(referenceNumber: uint16, wordCount: uint16): bool
                %{
                if ( ::modbus_request_read_multiple_register )
                        {
                        BifEvent::generate_modbus_request_read_multiple_register(
                                connection()->bro_analyzer(),
                                connection()->bro_analyzer()->Conn(),
                                is_orig(), referenceNumber, wordCount);
                        }

                return true;
                %}

	# Hui Lin
	# WriteMultipleRegistersRequest
	# To read the value in the register, call another event handler. 
	function get_modbus_request_write_multiple_register(referenceNumber: uint16, wordCount: uint16, byteCount: uint8 ): bool
                %{
                if ( ::modbus_request_write_multiple_register )
                        {
                        BifEvent::generate_modbus_request_write_multiple_register(
                                connection()->bro_analyzer(),
                                connection()->bro_analyzer()->Conn(),
                                is_orig(), referenceNumber, wordCount, byteCount);
                        }

                return true;
                %}

	# class 1
	# Hui Lin
	# RegisterUnit
	function get_modbus_register_unit(ru: uint16 ): bool
                %{
                if ( ::modbus_register_unit )
                        {
                        BifEvent::generate_modbus_register_unit(
                                connection()->bro_analyzer(),
                                connection()->bro_analyzer()->Conn(),
                                is_orig(), ru );
                        }

                return true;
                %}

	# Hui Lin
	# ReadCoilsRequest
	function get_modbus_request_read_coil(ru: uint16, bitCount: uint16): bool
                %{
                if ( ::modbus_request_read_coil )
                        {
                        BifEvent::generate_modbus_request_read_coil(
                                connection()->bro_analyzer(),
                                connection()->bro_analyzer()->Conn(),
                                is_orig(), ru, bitCount);
                        }

                return true;
                %}

	# Hui Lin
	# ReadInputDiscretesRequest
	function get_modbus_request_read_input_discrete(ru: uint16, bitCount: uint16): bool
                %{
                if ( ::modbus_request_read_input_discrete )
                        {
                        BifEvent::generate_modbus_request_read_input_discrete(
                                connection()->bro_analyzer(),
                                connection()->bro_analyzer()->Conn(),
                                is_orig(), ru, bitCount);
                        }

                return true;
                %}

	# Hui Lin
	# ReadInputRegistersRequest
	function get_modbus_request_read_input_register(referenceNumber: uint16, wordCount: uint16): bool
                %{
                if ( ::modbus_request_read_input_register )
                        {
                        BifEvent::generate_modbus_request_read_input_register(
                                connection()->bro_analyzer(),
                                connection()->bro_analyzer()->Conn(),
                                is_orig(), referenceNumber, wordCount);
                        }

                return true;
                %}
	
	# Hui Lin
	# WriteCoilRequest
	function get_modbus_request_write_coil(referenceNumber: uint16, onoff: uint8, other: uint8): bool
                %{
                if ( ::modbus_request_write_coil )
                        {
                        BifEvent::generate_modbus_request_write_coil(
                                connection()->bro_analyzer(),
                                connection()->bro_analyzer()->Conn(),
                                is_orig(), referenceNumber, onoff, other);
                        }

                return true;
                %}


	# Hui Lin
	# WriteSingleRegisterRequest
	function get_modbus_request_write_single_register(referenceNumber: uint16, registervalue: uint16): bool
                %{
                if ( ::modbus_request_write_single_register )
                        {
                        BifEvent::generate_modbus_request_write_single_register(
                                connection()->bro_analyzer(),
                                connection()->bro_analyzer()->Conn(),
                                is_orig(), referenceNumber, registervalue);
                        }

                return true;
                %}


	# Hui Lin
	# ReadExceptionStatusRequest
	function get_modbus_request_read_exception_status(): bool
                %{
                if ( ::modbus_request_read_exception_status )
                        {
                        BifEvent::generate_modbus_request_read_exception_status(
                                connection()->bro_analyzer(),
                                connection()->bro_analyzer()->Conn(),
                                is_orig() );
                        }

                return true;
                %}

	# class 2
	# Hui Lin
	# ForceMultipleCoilsRequest
	function get_modbus_request_force_multiple_coils(ru: uint16, bitcount: uint8, bytecount: uint8, coil: const_bytestring): bool
                %{
                if ( ::modbus_request_force_multiple_coils )
                        {
                        BifEvent::generate_modbus_request_force_multiple_coils(
                                connection()->bro_analyzer(),
                                connection()->bro_analyzer()->Conn(),
                                is_orig(), ru, bitcount, bytecount, 
				bytestring_to_val(coil) );
                        }

                return true;
                %}
	
	# Hui Lin
	# ReadGeneralReferenceRequest
	function get_modbus_request_read_general_reference(bytecount: uint8): bool
                %{
                if ( ::modbus_request_read_general_reference )
                        {
                        BifEvent::generate_modbus_request_read_general_reference(
                                connection()->bro_analyzer(),
                                connection()->bro_analyzer()->Conn(),
                                is_orig(), bytecount);
                        }

                return true;
                %}

	# Hui Lin
	# WriteGeneralReferenceRequest
	function get_modbus_request_write_general_reference(bytecount: uint8): bool
                %{
                if ( ::modbus_request_write_general_reference )
                        {
                        BifEvent::generate_modbus_request_write_general_reference(
                                connection()->bro_analyzer(),
                                connection()->bro_analyzer()->Conn(),
                                is_orig(), bytecount );
                        }

                return true;
                %}

	# Hui Lin
	# Reference
	function get_modbus_reference(reftype: uint8, refnumber: uint32, wordcount: uint16): bool
                %{
                if ( ::modbus_reference )
                        {
                        BifEvent::generate_modbus_reference(
                                connection()->bro_analyzer(),
                                connection()->bro_analyzer()->Conn(),
                                is_orig(), reftype, refnumber, wordcount );
                        }

                return true;
                %}

	# Hui Lin
	# ReferenceWithData
	function get_modbus_reference_with_data(reftype: uint8, refnumber: uint32, wordcount: uint16): bool
                %{
                if ( ::modbus_reference_with_data )
                        {
                        BifEvent::generate_modbus_reference_with_data(
                                connection()->bro_analyzer(),
                                connection()->bro_analyzer()->Conn(),
                                is_orig(), reftype, refnumber, wordcount );
                        }

                return true;
                %}

	# Hui Lin
	# RegisterValueUnit
	function get_modbus_register_value_unit(rvu: uint16): bool
                %{
                if ( ::modbus_register_value_unit )
                        {
                        BifEvent::generate_modbus_register_value_unit(
                                connection()->bro_analyzer(),
                                connection()->bro_analyzer()->Conn(),
                                is_orig(), rvu );
                        }

                return true;
                %}

	# Hui Lin
	# MaskWriteRegisterRequest
	function get_modbus_reguest_mask_write_register(refnumber: uint16, andmask: uint16, ormask: uint16): bool
                %{
                if ( ::modbus_request_mask_write_register )
                        {
                        BifEvent::generate_modbus_request_mask_write_register(
                                connection()->bro_analyzer(),
                                connection()->bro_analyzer()->Conn(),
                                is_orig(), refnumber, andmask, ormask );
                        }

                return true;
                %}
	
	# Hui Lin
	# ReadWriteRegistersRequest
	function get_modbus_request_read_write_registers(refnumber: uint16, wordcountread: uint16, refnumberwrite: uint16, wordcountwrite: uint16,
									bytecount: uint16 ): bool
                %{
                if ( ::modbus_request_read_write_registers )
                        {
                        BifEvent::generate_modbus_request_read_write_registers(
                                connection()->bro_analyzer(),
                                connection()->bro_analyzer()->Conn(),
                                is_orig(), refnumber, wordcountread, refnumberwrite, wordcountwrite, bytecount );
                        }

                return true;
                %}


	# Hui Lin
	# ReadFIFOQueueRequest
	function get_modbus_request_read_FIFO_queue(refnumber: uint16): bool
                %{
                if ( ::modbus_request_read_FIFO_queue )
                        {
                        BifEvent::generate_modbus_request_read_FIFO_queue(
                                connection()->bro_analyzer(),
                                connection()->bro_analyzer()->Conn(),
                                is_orig(), refnumber );
                        }

                return true;
                %}


	


};

refine typeattr ModbusTCP_RequestPDU += &let {
        process_request: bool =  $context.flow.get_modbus_request(header.len+6);
};

refine typeattr ModbusTCP_TransportHeader += &let {
        process_request: bool =  $context.flow.get_modbus_header(tid, pid, len, uid, fc);
};

refine typeattr ReadMultipleRegistersRequest += &let {
        process_request: bool =  $context.flow.get_modbus_request_read_multiple_register(referenceNumber, wordCount);
};

refine typeattr WriteMultipleRegistersRequest += &let {
        process_request: bool =  $context.flow.get_modbus_request_write_multiple_register(referenceNumber, wordCount, byteCount);
};
