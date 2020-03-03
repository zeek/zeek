#
# The development of Bro's Modbus analyzer has been made possible thanks to
# the support of the Ministry of Security and Justice of the Kingdom of the
# Netherlands within the projects of Hermes, Castor and Midas.
#
# Useful references: http://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf
#                    http://www.simplymodbus.ca/faq.htm
#

%header{
	VectorVal* bytestring_to_coils(const bytestring& coils, uint quantity);
	RecordVal* HeaderToBro(ModbusTCP_TransportHeader *header);
	VectorVal* create_vector_of_count();
	%}

%code{
	VectorVal* bytestring_to_coils(const bytestring& coils, uint quantity)
		{
		VectorVal* modbus_coils = new VectorVal(BifType::Vector::ModbusCoils);
		for ( uint i = 0; i < quantity; i++ )
			{
			char currentCoil = (coils[i/8] >> (i % 8)) % 2;
			modbus_coils->Assign(i, val_mgr->GetBool(currentCoil));
			}

		return modbus_coils;
		}

	RecordVal* HeaderToBro(ModbusTCP_TransportHeader *header)
		{
		RecordVal* modbus_header = new RecordVal(BifType::Record::ModbusHeaders);
		modbus_header->Assign(0, val_mgr->GetCount(header->tid()));
		modbus_header->Assign(1, val_mgr->GetCount(header->pid()));
		modbus_header->Assign(2, val_mgr->GetCount(header->uid()));
		modbus_header->Assign(3, val_mgr->GetCount(header->fc()));
		return modbus_header;
		}

	VectorVal* create_vector_of_count()
		{
		VectorType* vt = new VectorType(base_type(TYPE_COUNT));
		VectorVal* vv = new VectorVal(vt);
		Unref(vt);
		return vv;
		}

	%}

refine connection ModbusTCP_Conn += {
	%member{
		// Fields used to determine if the protocol has been confirmed or not.
		bool confirmed;
		bool orig_pdu;
		bool resp_pdu;
		%}

	%init{
		confirmed = false;
		orig_pdu = false;
		resp_pdu = false;
		%}

	function SetPDU(is_orig: bool): bool
		%{
		if ( is_orig )
			orig_pdu = true;
		else
			resp_pdu = true;

		return true;
		%}

	function SetConfirmed(): bool
		%{
		confirmed = true;
		return true;
		%}

	function IsConfirmed(): bool
		%{
		return confirmed && orig_pdu && resp_pdu;
		%}
};

refine flow ModbusTCP_Flow += {

	function deliver_message(header: ModbusTCP_TransportHeader): bool
		%{
		if ( ::modbus_message )
			{
			BifEvent::generate_modbus_message(connection()->bro_analyzer(),
			                                  connection()->bro_analyzer()->Conn(),
			                                  HeaderToBro(header),
			                                  is_orig());
			}

		return true;
		%}

	function deliver_ModbusTCP_PDU(message: ModbusTCP_PDU): bool
		%{
		// We will assume that if an entire PDU from both sides
		// is successfully parsed then this is definitely modbus.
		connection()->SetPDU(${message.is_orig});

		if ( ! connection()->IsConfirmed() )
			{
			connection()->SetConfirmed();
			connection()->bro_analyzer()->ProtocolConfirmation();
			}

		return true;
		%}

	# EXCEPTION
	function deliver_Exception(header: ModbusTCP_TransportHeader, message: Exception): bool
		%{
		if ( ::modbus_exception )
			{
			BifEvent::generate_modbus_exception(connection()->bro_analyzer(),
			                                    connection()->bro_analyzer()->Conn(),
			                                    HeaderToBro(header),
			                                    ${message.code});
			}

		return true;
		%}

	# REQUEST FC=1
	function deliver_ReadCoilsRequest(header: ModbusTCP_TransportHeader, message: ReadCoilsRequest): bool
		%{
		if ( ::modbus_read_coils_request )
			{
			BifEvent::generate_modbus_read_coils_request(connection()->bro_analyzer(),
			                                             connection()->bro_analyzer()->Conn(),
			                                             HeaderToBro(header),
			                                             ${message.start_address},
			                                             ${message.quantity});
			}

		return true;
		%}

	# RESPONSE FC=1
	function deliver_ReadCoilsResponse(header: ModbusTCP_TransportHeader, message: ReadCoilsResponse): bool
		%{
		if ( ::modbus_read_coils_response )
			{
			BifEvent::generate_modbus_read_coils_response(connection()->bro_analyzer(),
			                                              connection()->bro_analyzer()->Conn(),
			                                              HeaderToBro(header),
			                                              bytestring_to_coils(${message.bits}, ${message.bits}.length()*8));
			}
		return true;
		%}

	# REQUEST FC=2
	function deliver_ReadDiscreteInputsRequest(header: ModbusTCP_TransportHeader, message: ReadDiscreteInputsRequest): bool
		%{
		if ( ::modbus_read_discrete_inputs_request )
			{
			BifEvent::generate_modbus_read_discrete_inputs_request(connection()->bro_analyzer(),
			                                                       connection()->bro_analyzer()->Conn(),
			                                                       HeaderToBro(header),
			                                                       ${message.start_address}, ${message.quantity});
			}

		return true;
		%}

	# RESPONSE FC=2
	function deliver_ReadDiscreteInputsResponse(header: ModbusTCP_TransportHeader, message: ReadDiscreteInputsResponse): bool
		%{
		if ( ::modbus_read_discrete_inputs_response )
			{
			BifEvent::generate_modbus_read_discrete_inputs_response(connection()->bro_analyzer(),
			                                                        connection()->bro_analyzer()->Conn(),
			                                                        HeaderToBro(header),
			                                                        bytestring_to_coils(${message.bits}, ${message.bits}.length()*8));
			}

		return true;
		%}


	# REQUEST FC=3
	function deliver_ReadHoldingRegistersRequest(header: ModbusTCP_TransportHeader, message: ReadHoldingRegistersRequest): bool
		%{
		if ( ::modbus_read_holding_registers_request )
			{
			BifEvent::generate_modbus_read_holding_registers_request(connection()->bro_analyzer(),
			                                                         connection()->bro_analyzer()->Conn(),
			                                                         HeaderToBro(header),
			                                                         ${message.start_address}, ${message.quantity});
			}

		return true;
		%}

	# RESPONSE FC=3
	function deliver_ReadHoldingRegistersResponse(header: ModbusTCP_TransportHeader, message: ReadHoldingRegistersResponse): bool
		%{
		if ( ${message.byte_count} % 2 != 0 )
			{
			connection()->bro_analyzer()->ProtocolViolation(
			    fmt("invalid value for modbus read holding register response byte count %d", ${message.byte_count}));
			return false;
			}

		if ( ::modbus_read_holding_registers_response )
			{

			VectorVal* t = new VectorVal(BifType::Vector::ModbusRegisters);
			for ( unsigned int i=0; i < ${message.registers}->size(); ++i )
				{
				Val* r = val_mgr->GetCount(${message.registers[i]});
				t->Assign(i, r);
				}

			BifEvent::generate_modbus_read_holding_registers_response(connection()->bro_analyzer(),
			                                                          connection()->bro_analyzer()->Conn(),
			                                                          HeaderToBro(header),
			                                                          t);
			}

		return true;
		%}


	# REQUEST FC=4
	function deliver_ReadInputRegistersRequest(header: ModbusTCP_TransportHeader, message: ReadInputRegistersRequest): bool
		%{
		if ( ::modbus_read_input_registers_request )
			{
			BifEvent::generate_modbus_read_input_registers_request(connection()->bro_analyzer(),
			                                                       connection()->bro_analyzer()->Conn(),
			                                                       HeaderToBro(header),
			                                                       ${message.start_address}, ${message.quantity});
			}

		return true;
		%}

	# RESPONSE FC=4
	function deliver_ReadInputRegistersResponse(header: ModbusTCP_TransportHeader, message: ReadInputRegistersResponse): bool
		%{
		if ( ${message.byte_count} % 2 != 0 )
			{
			connection()->bro_analyzer()->ProtocolViolation(
			    fmt("invalid value for modbus read input register response byte count %d", ${message.byte_count}));
			return false;
			}

		if ( ::modbus_read_input_registers_response )
			{
			VectorVal* t = new VectorVal(BifType::Vector::ModbusRegisters);
			for ( unsigned int i=0; i < (${message.registers})->size(); ++i )
				{
				Val* r = val_mgr->GetCount(${message.registers[i]});
				t->Assign(i, r);
				}

			BifEvent::generate_modbus_read_input_registers_response(connection()->bro_analyzer(),
			                                                        connection()->bro_analyzer()->Conn(),
			                                                        HeaderToBro(header),
			                                                        t);
			}

		return true;
		%}


	# REQUEST FC=5
	function deliver_WriteSingleCoilRequest(header: ModbusTCP_TransportHeader, message: WriteSingleCoilRequest): bool
		%{
		if ( ::modbus_write_single_coil_request )
			{
			int val;
			if ( ${message.value} == 0x0000 )
				val = 0;
			else if ( ${message.value} == 0xFF00 )
				val = 1;
			else
				{
				connection()->bro_analyzer()->ProtocolViolation(fmt("invalid value for modbus write single coil request %d",
				                                                    ${message.value}));
				return false;
				}

			BifEvent::generate_modbus_write_single_coil_request(connection()->bro_analyzer(),
			                                                    connection()->bro_analyzer()->Conn(),
			                                                    HeaderToBro(header),
			                                                    ${message.address},
			                                                    val);
			}

		return true;
		%}

	# RESPONSE FC=5
	function deliver_WriteSingleCoilResponse(header: ModbusTCP_TransportHeader, message: WriteSingleCoilResponse): bool
		%{
		if ( ::modbus_write_single_coil_response )
			{
			int val;
			if ( ${message.value} == 0x0000 )
				val = 0;
			else if ( ${message.value} == 0xFF00 )
				val = 1;
			else
				{
				connection()->bro_analyzer()->ProtocolViolation(fmt("invalid value for modbus write single coil response %d",
				                                                    ${message.value}));
				return false;
				}

			BifEvent::generate_modbus_write_single_coil_response(connection()->bro_analyzer(),
			                                                     connection()->bro_analyzer()->Conn(),
			                                                     HeaderToBro(header),
			                                                     ${message.address},
			                                                     val);
			}

		return true;
		%}


	# REQUEST FC=6
	function deliver_WriteSingleRegisterRequest(header: ModbusTCP_TransportHeader, message: WriteSingleRegisterRequest): bool
		%{
		if ( ::modbus_write_single_register_request )
			{
			BifEvent::generate_modbus_write_single_register_request(connection()->bro_analyzer(),
			                                                        connection()->bro_analyzer()->Conn(),
			                                                        HeaderToBro(header),
			                                                        ${message.address}, ${message.value});
			}

		return true;
		%}

	# RESPONSE FC=6
	function deliver_WriteSingleRegisterResponse(header: ModbusTCP_TransportHeader, message: WriteSingleRegisterResponse): bool
		%{
		if ( ::modbus_write_single_register_response )
			{
			BifEvent::generate_modbus_write_single_register_response(connection()->bro_analyzer(),
			                                                         connection()->bro_analyzer()->Conn(),
			                                                         HeaderToBro(header),
			                                                         ${message.address}, ${message.value});
			}

		return true;
		%}


	# REQUEST FC=15
	function deliver_WriteMultipleCoilsRequest(header: ModbusTCP_TransportHeader, message: WriteMultipleCoilsRequest): bool
		%{
		if ( ::modbus_write_multiple_coils_request )
			{
			BifEvent::generate_modbus_write_multiple_coils_request(connection()->bro_analyzer(),
			                                                       connection()->bro_analyzer()->Conn(),
			                                                       HeaderToBro(header),
			                                                       ${message.start_address},
			                                                       bytestring_to_coils(${message.coils}, ${message.quantity}));
			}

		return true;
		%}

	# RESPONSE FC=15
	function deliver_WriteMultipleCoilsResponse(header: ModbusTCP_TransportHeader, message: WriteMultipleCoilsResponse): bool
		%{
		if ( ::modbus_write_multiple_coils_response )
			{
			BifEvent::generate_modbus_write_multiple_coils_response(connection()->bro_analyzer(),
			                                                        connection()->bro_analyzer()->Conn(),
			                                                        HeaderToBro(header),
			                                                        ${message.start_address}, ${message.quantity});
			}

		return true;
		%}


	# REQUEST FC=16
	function deliver_WriteMultipleRegistersRequest(header: ModbusTCP_TransportHeader, message: WriteMultipleRegistersRequest): bool
		%{
		if ( ${message.byte_count} % 2 != 0 )
			{
			connection()->bro_analyzer()->ProtocolViolation(
			    fmt("invalid value for modbus write multiple registers request byte count %d", ${message.byte_count}));
			return false;
			}

		if ( ::modbus_write_multiple_registers_request )
			{
			VectorVal * t = new VectorVal(BifType::Vector::ModbusRegisters);
			for ( unsigned int i = 0; i < (${message.registers}->size()); ++i )
				{
				Val* r = val_mgr->GetCount(${message.registers[i]});
				t->Assign(i, r);
				}

				BifEvent::generate_modbus_write_multiple_registers_request(connection()->bro_analyzer(),
				                                                           connection()->bro_analyzer()->Conn(),
				                                                           HeaderToBro(header),
				                                                           ${message.start_address}, t);
			}

		return true;
		%}

	# RESPONSE FC=16
	function deliver_WriteMultipleRegistersResponse(header: ModbusTCP_TransportHeader, message: WriteMultipleRegistersResponse): bool
		%{
		if ( ::modbus_write_multiple_registers_response )
			{
			BifEvent::generate_modbus_write_multiple_registers_response(connection()->bro_analyzer(),
			                                                            connection()->bro_analyzer()->Conn(),
			                                                            HeaderToBro(header),
			                                                            ${message.start_address}, ${message.quantity});
			}

		return true;
		%}

	# REQUEST FC=20
	function deliver_ReadFileRecordRequest(header: ModbusTCP_TransportHeader, message: ReadFileRecordRequest): bool
		%{
		if ( ::modbus_read_file_record_request )
			{
			//TODO: this need to be a vector of some Reference Request record type
			//VectorVal *t = create_vector_of_count();
			//for ( unsigned int i = 0; i < (${message.references}->size()); ++i )
			//	{
			//	Val* r = val_mgr->GetCount((${message.references[i].ref_type}));
			//	t->Assign(i, r);
			//
			//	Val* k = val_mgr->GetCount((${message.references[i].file_num}));
			//	t->Assign(i, k);
			//
			//	Val* l = val_mgr->GetCount((${message.references[i].record_num}));
			//	t->Assign(i, l);
			//	}

			BifEvent::generate_modbus_read_file_record_request(connection()->bro_analyzer(),
			                                                   connection()->bro_analyzer()->Conn(),
			                                                   HeaderToBro(header));
			}

		return true;
		%}

	# RESPONSE FC=20
	function deliver_ReadFileRecordResponse(header: ModbusTCP_TransportHeader, message: ReadFileRecordResponse): bool
		%{
		if ( ::modbus_read_file_record_response )
			{
			//VectorVal *t = create_vector_of_count();
			//for ( unsigned int i = 0; i < ${message.references}->size(); ++i )
			//	{
			//	//TODO: work the reference type in here somewhere
			//	Val* r = val_mgr->GetCount(${message.references[i].record_data}));
			//	t->Assign(i, r);
			//	}

			BifEvent::generate_modbus_read_file_record_response(connection()->bro_analyzer(),
			                                                    connection()->bro_analyzer()->Conn(),
			                                                    HeaderToBro(header));
			}

		return true;
		%}

	# REQUEST FC=21
	function deliver_WriteFileRecordRequest(header: ModbusTCP_TransportHeader, message: WriteFileRecordRequest): bool
		%{
		if ( ::modbus_write_file_record_request )
			{
			//VectorVal* t = create_vector_of_count();
			//for ( unsigned int i = 0; i < (${message.references}->size()); ++i )
			//	{
			//	Val* r = val_mgr->GetCount((${message.references[i].ref_type}));
			//	t->Assign(i, r);
			//
			//	Val* k = val_mgr->GetCount((${message.references[i].file_num}));
			//	t->Assign(i, k);
			//
			//	Val* n = val_mgr->GetCount((${message.references[i].record_num}));
			//	t->Assign(i, n);
			//
			//	for ( unsigned int j = 0; j < (${message.references[i].register_value}->size()); ++j )
			//		{
			//		k = val_mgr->GetCount((${message.references[i].register_value[j]}));
			//		t->Assign(i, k);
			//		}
			//	}

			BifEvent::generate_modbus_write_file_record_request(connection()->bro_analyzer(),
			                                                    connection()->bro_analyzer()->Conn(),
			                                                    HeaderToBro(header));
			}

		return true;
		%}


	# RESPONSE FC=21
	function deliver_WriteFileRecordResponse(header: ModbusTCP_TransportHeader, message: WriteFileRecordResponse): bool
		%{
		if ( ::modbus_write_file_record_response )
			{
			//VectorVal* t = create_vector_of_count();
			//for ( unsigned int i = 0; i < (${messages.references}->size()); ++i )
			//	{
			//	Val* r = val_mgr->GetCount((${message.references[i].ref_type}));
			//	t->Assign(i, r);
			//
			//	Val* f = val_mgr->GetCount((${message.references[i].file_num}));
			//	t->Assign(i, f);
			//
			//	Val* rn = val_mgr->GetCount((${message.references[i].record_num}));
			//	t->Assign(i, rn);
			//
			//	for ( unsigned int j = 0; j<(${message.references[i].register_value}->size()); ++j )
			//		{
			//		Val* k = val_mgr->GetCount((${message.references[i].register_value[j]}));
			//		t->Assign(i, k);
			//		}

			BifEvent::generate_modbus_write_file_record_response(connection()->bro_analyzer(),
			                                                     connection()->bro_analyzer()->Conn(),
			                                                     HeaderToBro(header));
			}

		return true;
		%}

	# REQUEST FC=22
	function deliver_MaskWriteRegisterRequest(header: ModbusTCP_TransportHeader, message: MaskWriteRegisterRequest): bool
		%{
		if ( ::modbus_mask_write_register_request )
			{
			BifEvent::generate_modbus_mask_write_register_request(connection()->bro_analyzer(),
			                                                      connection()->bro_analyzer()->Conn(),
			                                                      HeaderToBro(header),
			                                                      ${message.address},
			                                                      ${message.and_mask}, ${message.or_mask});
			}

		return true;
		%}

	# RESPONSE FC=22
	function deliver_MaskWriteRegisterResponse(header: ModbusTCP_TransportHeader, message: MaskWriteRegisterResponse): bool
		%{
		if ( ::modbus_mask_write_register_response )
			{
			BifEvent::generate_modbus_mask_write_register_response(connection()->bro_analyzer(),
			                                                       connection()->bro_analyzer()->Conn(),
			                                                       HeaderToBro(header),
			                                                       ${message.address},
			                                                       ${message.and_mask}, ${message.or_mask});
			}

		return true;
		%}

	# REQUEST FC=23
	function deliver_ReadWriteMultipleRegistersRequest(header: ModbusTCP_TransportHeader, message: ReadWriteMultipleRegistersRequest): bool
		%{
		if ( ${message.write_byte_count} % 2 != 0 )
			{
			connection()->bro_analyzer()->ProtocolViolation(
			    fmt("invalid value for modbus read write multiple registers request write byte count %d", ${message.write_byte_count}));
			return false;
			}

		if ( ::modbus_read_write_multiple_registers_request )
			{
			VectorVal* t = new VectorVal(BifType::Vector::ModbusRegisters);
			for ( unsigned int i = 0; i < ${message.write_register_values}->size(); ++i )
				{
				Val* r = val_mgr->GetCount(${message.write_register_values[i]});
				t->Assign(i, r);
				}

			BifEvent::generate_modbus_read_write_multiple_registers_request(connection()->bro_analyzer(),
			                                                                connection()->bro_analyzer()->Conn(),
			                                                                HeaderToBro(header),
			                                                                ${message.read_start_address},
			                                                                ${message.read_quantity},
			                                                                ${message.write_start_address},
			                                                                t);
			}

		return true;
		%}

	# RESPONSE FC=23
	function deliver_ReadWriteMultipleRegistersResponse(header: ModbusTCP_TransportHeader, message: ReadWriteMultipleRegistersResponse): bool
		%{
		if ( ${message.byte_count} % 2 != 0 )
			{
			connection()->bro_analyzer()->ProtocolViolation(
			    fmt("invalid value for modbus read write multiple registers response byte count %d", ${message.byte_count}));
			return false;
			}

		if ( ::modbus_read_write_multiple_registers_response )
			{
			VectorVal* t = new VectorVal(BifType::Vector::ModbusRegisters);
			for ( unsigned int i = 0; i < ${message.registers}->size(); ++i )
				{
				Val* r = val_mgr->GetCount(${message.registers[i]});
				t->Assign(i, r);
				}

			BifEvent::generate_modbus_read_write_multiple_registers_response(connection()->bro_analyzer(),
			                                                                 connection()->bro_analyzer()->Conn(),
			                                                                 HeaderToBro(header),
			                                                                 t);
			}

		return true;
		%}

	# REQUEST FC=24
	function deliver_ReadFIFOQueueRequest(header: ModbusTCP_TransportHeader, message: ReadFIFOQueueRequest): bool
		%{
		if ( ::modbus_read_fifo_queue_request )
			{
			BifEvent::generate_modbus_read_fifo_queue_request(connection()->bro_analyzer(),
			                                                  connection()->bro_analyzer()->Conn(),
			                                                  HeaderToBro(header),
			                                                  ${message.start_address});
			}

		return true;
		%}


	# RESPONSE FC=24
	function deliver_ReadFIFOQueueResponse(header: ModbusTCP_TransportHeader, message: ReadFIFOQueueResponse): bool
		%{
		if ( ${message.byte_count} % 2 != 0 )
			{
			connection()->bro_analyzer()->ProtocolViolation(
			    fmt("invalid value for modbus read FIFO queue response byte count %d", ${message.byte_count}));
			return false;
			}

		if ( ::modbus_read_fifo_queue_response )
			{
			VectorVal* t = create_vector_of_count();
			for ( unsigned int i = 0; i < (${message.register_data})->size(); ++i )
				{
				Val* r = val_mgr->GetCount(${message.register_data[i]});
				t->Assign(i, r);
				}

			BifEvent::generate_modbus_read_fifo_queue_response(connection()->bro_analyzer(),
			                                                   connection()->bro_analyzer()->Conn(),
			                                                   HeaderToBro(header),
			                                                   t);
			}

		return true;
		%}
};
