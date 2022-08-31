#
# The development of Zeek's Modbus analyzer has been made possible thanks to
# the support of the Ministry of Security and Justice of the Kingdom of the
# Netherlands within the projects of Hermes, Castor and Midas.
#
# Useful references: http://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf
#                    http://www.simplymodbus.ca/faq.htm
#

%header{
	zeek::VectorValPtr bytestring_to_coils(const bytestring& coils, uint quantity);
	zeek::RecordValPtr HeaderToVal(ModbusTCP_TransportHeader* header);
	zeek::VectorValPtr create_vector_of_count();
	%}

%code{
	zeek::VectorValPtr bytestring_to_coils(const bytestring& coils, uint quantity)
		{
		auto modbus_coils = zeek::make_intrusive<zeek::VectorVal>(zeek::BifType::Vector::ModbusCoils);

		for ( uint i = 0; i < quantity && (i/8) < static_cast<uint>(coils.length()); i++ )
			{
			char currentCoil = (coils[i/8] >> (i % 8)) % 2;
			modbus_coils->Assign(i, zeek::val_mgr->Bool(currentCoil));
			}

		return modbus_coils;
		}

	zeek::RecordValPtr HeaderToVal(ModbusTCP_TransportHeader* header)
		{
		auto modbus_header = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::ModbusHeaders);
		modbus_header->Assign(0, header->tid());
		modbus_header->Assign(1, header->pid());
		modbus_header->Assign(2, header->uid());
		modbus_header->Assign(3, header->fc());
		return modbus_header;
		}

	zeek::VectorValPtr create_vector_of_count()
		{
		auto vt = zeek::make_intrusive<zeek::VectorType>(zeek::base_type(zeek::TYPE_COUNT));
		auto vv = zeek::make_intrusive<zeek::VectorVal>(std::move(vt));
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
			zeek::BifEvent::enqueue_modbus_message(connection()->zeek_analyzer(),
			                                 connection()->zeek_analyzer()->Conn(),
			                                 HeaderToVal(header),
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
			connection()->zeek_analyzer()->AnalyzerConfirmation();
			}

		return true;
		%}

	# EXCEPTION
	function deliver_Exception(header: ModbusTCP_TransportHeader, message: Exception): bool
		%{
		if ( ::modbus_exception )
			{
			zeek::BifEvent::enqueue_modbus_exception(connection()->zeek_analyzer(),
			                                   connection()->zeek_analyzer()->Conn(),
			                                   HeaderToVal(header),
			                                   ${message.code});
			}

		return true;
		%}

	# REQUEST FC=1
	function deliver_ReadCoilsRequest(header: ModbusTCP_TransportHeader, message: ReadCoilsRequest): bool
		%{
		if ( ::modbus_read_coils_request )
			{
			zeek::BifEvent::enqueue_modbus_read_coils_request(connection()->zeek_analyzer(),
			                                            connection()->zeek_analyzer()->Conn(),
			                                            HeaderToVal(header),
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
			zeek::BifEvent::enqueue_modbus_read_coils_response(connection()->zeek_analyzer(),
			                                             connection()->zeek_analyzer()->Conn(),
			                                             HeaderToVal(header),
			                                             bytestring_to_coils(${message.bits}, ${message.bits}.length()*8));
			}
		return true;
		%}

	# REQUEST FC=2
	function deliver_ReadDiscreteInputsRequest(header: ModbusTCP_TransportHeader, message: ReadDiscreteInputsRequest): bool
		%{
		if ( ::modbus_read_discrete_inputs_request )
			{
			zeek::BifEvent::enqueue_modbus_read_discrete_inputs_request(connection()->zeek_analyzer(),
			                                                      connection()->zeek_analyzer()->Conn(),
			                                                      HeaderToVal(header),
			                                                      ${message.start_address}, ${message.quantity});
			}

		return true;
		%}

	# RESPONSE FC=2
	function deliver_ReadDiscreteInputsResponse(header: ModbusTCP_TransportHeader, message: ReadDiscreteInputsResponse): bool
		%{
		if ( ::modbus_read_discrete_inputs_response )
			{
			zeek::BifEvent::enqueue_modbus_read_discrete_inputs_response(connection()->zeek_analyzer(),
			                                                       connection()->zeek_analyzer()->Conn(),
			                                                       HeaderToVal(header),
			                                                       bytestring_to_coils(${message.bits}, ${message.bits}.length()*8));
			}

		return true;
		%}


	# REQUEST FC=3
	function deliver_ReadHoldingRegistersRequest(header: ModbusTCP_TransportHeader, message: ReadHoldingRegistersRequest): bool
		%{
		if ( ::modbus_read_holding_registers_request )
			{
			zeek::BifEvent::enqueue_modbus_read_holding_registers_request(connection()->zeek_analyzer(),
			                                                        connection()->zeek_analyzer()->Conn(),
			                                                        HeaderToVal(header),
			                                                        ${message.start_address}, ${message.quantity});
			}

		return true;
		%}

	# RESPONSE FC=3
	function deliver_ReadHoldingRegistersResponse(header: ModbusTCP_TransportHeader, message: ReadHoldingRegistersResponse): bool
		%{
		if ( ${message.byte_count} % 2 != 0 )
			{
			connection()->zeek_analyzer()->AnalyzerViolation(
			    zeek::util::fmt("invalid value for modbus read holding register response byte count %d", ${message.byte_count}));
			return false;
			}

		if ( ::modbus_read_holding_registers_response )
			{
			auto t = zeek::make_intrusive<zeek::VectorVal>(zeek::BifType::Vector::ModbusRegisters);

			for ( unsigned int i=0; i < ${message.registers}->size(); ++i )
				{
				auto r = zeek::val_mgr->Count(${message.registers[i]});
				t->Assign(i, r);
				}

			zeek::BifEvent::enqueue_modbus_read_holding_registers_response(connection()->zeek_analyzer(),
			                                                         connection()->zeek_analyzer()->Conn(),
			                                                         HeaderToVal(header),
			                                                         std::move(t));
			}

		return true;
		%}


	# REQUEST FC=4
	function deliver_ReadInputRegistersRequest(header: ModbusTCP_TransportHeader, message: ReadInputRegistersRequest): bool
		%{
		if ( ::modbus_read_input_registers_request )
			{
			zeek::BifEvent::enqueue_modbus_read_input_registers_request(connection()->zeek_analyzer(),
			                                                      connection()->zeek_analyzer()->Conn(),
			                                                      HeaderToVal(header),
			                                                      ${message.start_address}, ${message.quantity});
			}

		return true;
		%}

	# RESPONSE FC=4
	function deliver_ReadInputRegistersResponse(header: ModbusTCP_TransportHeader, message: ReadInputRegistersResponse): bool
		%{
		if ( ${message.byte_count} % 2 != 0 )
			{
			connection()->zeek_analyzer()->AnalyzerViolation(
			    zeek::util::fmt("invalid value for modbus read input register response byte count %d", ${message.byte_count}));
			return false;
			}

		if ( ::modbus_read_input_registers_response )
			{
			auto t = zeek::make_intrusive<zeek::VectorVal>(zeek::BifType::Vector::ModbusRegisters);

			for ( unsigned int i=0; i < (${message.registers})->size(); ++i )
				{
				auto r = zeek::val_mgr->Count(${message.registers[i]});
				t->Assign(i, r);
				}

			zeek::BifEvent::enqueue_modbus_read_input_registers_response(connection()->zeek_analyzer(),
			                                                       connection()->zeek_analyzer()->Conn(),
			                                                       HeaderToVal(header),
			                                                       std::move(t));
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
				connection()->zeek_analyzer()->AnalyzerViolation(zeek::util::fmt("invalid value for modbus write single coil request %d",
				                                                    ${message.value}));
				return false;
				}

			zeek::BifEvent::enqueue_modbus_write_single_coil_request(connection()->zeek_analyzer(),
			                                                   connection()->zeek_analyzer()->Conn(),
			                                                   HeaderToVal(header),
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
				connection()->zeek_analyzer()->AnalyzerViolation(zeek::util::fmt("invalid value for modbus write single coil response %d",
				                                                    ${message.value}));
				return false;
				}

			zeek::BifEvent::enqueue_modbus_write_single_coil_response(connection()->zeek_analyzer(),
			                                                    connection()->zeek_analyzer()->Conn(),
			                                                    HeaderToVal(header),
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
			zeek::BifEvent::enqueue_modbus_write_single_register_request(connection()->zeek_analyzer(),
			                                                       connection()->zeek_analyzer()->Conn(),
			                                                       HeaderToVal(header),
			                                                       ${message.address}, ${message.value});
			}

		return true;
		%}

	# RESPONSE FC=6
	function deliver_WriteSingleRegisterResponse(header: ModbusTCP_TransportHeader, message: WriteSingleRegisterResponse): bool
		%{
		if ( ::modbus_write_single_register_response )
			{
			zeek::BifEvent::enqueue_modbus_write_single_register_response(connection()->zeek_analyzer(),
			                                                        connection()->zeek_analyzer()->Conn(),
			                                                        HeaderToVal(header),
			                                                        ${message.address}, ${message.value});
			}

		return true;
		%}


	# REQUEST FC=15
	function deliver_WriteMultipleCoilsRequest(header: ModbusTCP_TransportHeader, message: WriteMultipleCoilsRequest): bool
		%{
		if ( ::modbus_write_multiple_coils_request )
			{
			zeek::BifEvent::enqueue_modbus_write_multiple_coils_request(connection()->zeek_analyzer(),
			                                                      connection()->zeek_analyzer()->Conn(),
			                                                      HeaderToVal(header),
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
			zeek::BifEvent::enqueue_modbus_write_multiple_coils_response(connection()->zeek_analyzer(),
			                                                       connection()->zeek_analyzer()->Conn(),
			                                                       HeaderToVal(header),
			                                                       ${message.start_address}, ${message.quantity});
			}

		return true;
		%}


	# REQUEST FC=16
	function deliver_WriteMultipleRegistersRequest(header: ModbusTCP_TransportHeader, message: WriteMultipleRegistersRequest): bool
		%{
		if ( ${message.byte_count} % 2 != 0 )
			{
			connection()->zeek_analyzer()->AnalyzerViolation(
			    zeek::util::fmt("invalid value for modbus write multiple registers request byte count %d", ${message.byte_count}));
			return false;
			}

		if ( ::modbus_write_multiple_registers_request )
			{
			auto t = zeek::make_intrusive<zeek::VectorVal>(zeek::BifType::Vector::ModbusRegisters);

			for ( unsigned int i = 0; i < (${message.registers}->size()); ++i )
				{
				auto r = zeek::val_mgr->Count(${message.registers[i]});
				t->Assign(i, r);
				}

				zeek::BifEvent::enqueue_modbus_write_multiple_registers_request(connection()->zeek_analyzer(),
				                                                          connection()->zeek_analyzer()->Conn(),
				                                                          HeaderToVal(header),
				                                                          ${message.start_address}, std::move(t));
			}

		return true;
		%}

	# RESPONSE FC=16
	function deliver_WriteMultipleRegistersResponse(header: ModbusTCP_TransportHeader, message: WriteMultipleRegistersResponse): bool
		%{
		if ( ::modbus_write_multiple_registers_response )
			{
			zeek::BifEvent::enqueue_modbus_write_multiple_registers_response(connection()->zeek_analyzer(),
			                                                           connection()->zeek_analyzer()->Conn(),
			                                                           HeaderToVal(header),
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
			//auto t = create_vector_of_count();
			//for ( unsigned int i = 0; i < (${message.references}->size()); ++i )
			//	{
			//	auto r = zeek::val_mgr->Count((${message.references[i].ref_type}));
			//	t->Assign(i, r);
			//
			//	auto k = zeek::val_mgr->Count((${message.references[i].file_num}));
			//	t->Assign(i, k);
			//
			//	auto l = zeek::val_mgr->Count((${message.references[i].record_num}));
			//	t->Assign(i, l);
			//	}

			zeek::BifEvent::enqueue_modbus_read_file_record_request(connection()->zeek_analyzer(),
			                                                  connection()->zeek_analyzer()->Conn(),
			                                                  HeaderToVal(header));
			}

		return true;
		%}

	# RESPONSE FC=20
	function deliver_ReadFileRecordResponse(header: ModbusTCP_TransportHeader, message: ReadFileRecordResponse): bool
		%{
		if ( ::modbus_read_file_record_response )
			{
			//auto t = create_vector_of_count();
			//for ( unsigned int i = 0; i < ${message.references}->size(); ++i )
			//	{
			//	//TODO: work the reference type in here somewhere
			//	auto r = zeek::val_mgr->Count(${message.references[i].record_data}));
			//	t->Assign(i, r);
			//	}

			zeek::BifEvent::enqueue_modbus_read_file_record_response(connection()->zeek_analyzer(),
			                                                   connection()->zeek_analyzer()->Conn(),
			                                                   HeaderToVal(header));
			}

		return true;
		%}

	# REQUEST FC=21
	function deliver_WriteFileRecordRequest(header: ModbusTCP_TransportHeader, message: WriteFileRecordRequest): bool
		%{
		if ( ::modbus_write_file_record_request )
			{
			//auto t = create_vector_of_count();
			//for ( unsigned int i = 0; i < (${message.references}->size()); ++i )
			//	{
			//	auto r = zeek::val_mgr->Count((${message.references[i].ref_type}));
			//	t->Assign(i, r);
			//
			//	auto k = zeek::val_mgr->Count((${message.references[i].file_num}));
			//	t->Assign(i, k);
			//
			//	auto n = zeek::val_mgr->Count((${message.references[i].record_num}));
			//	t->Assign(i, n);
			//
			//	for ( unsigned int j = 0; j < (${message.references[i].register_value}->size()); ++j )
			//		{
			//		k = zeek::val_mgr->Count((${message.references[i].register_value[j]}));
			//		t->Assign(i, k);
			//		}
			//	}

			zeek::BifEvent::enqueue_modbus_write_file_record_request(connection()->zeek_analyzer(),
			                                                   connection()->zeek_analyzer()->Conn(),
			                                                   HeaderToVal(header));
			}

		return true;
		%}


	# RESPONSE FC=21
	function deliver_WriteFileRecordResponse(header: ModbusTCP_TransportHeader, message: WriteFileRecordResponse): bool
		%{
		if ( ::modbus_write_file_record_response )
			{
			//auto t = create_vector_of_count();
			//for ( unsigned int i = 0; i < (${messages.references}->size()); ++i )
			//	{
			//	auto r = zeek::val_mgr->Count((${message.references[i].ref_type}));
			//	t->Assign(i, r);
			//
			//	auto f = zeek::val_mgr->Count((${message.references[i].file_num}));
			//	t->Assign(i, f);
			//
			//	auto rn = zeek::val_mgr->Count((${message.references[i].record_num}));
			//	t->Assign(i, rn);
			//
			//	for ( unsigned int j = 0; j<(${message.references[i].register_value}->size()); ++j )
			//		{
			//		auto k = zeek::val_mgr->Count((${message.references[i].register_value[j]}));
			//		t->Assign(i, k);
			//		}

			zeek::BifEvent::enqueue_modbus_write_file_record_response(connection()->zeek_analyzer(),
			                                                    connection()->zeek_analyzer()->Conn(),
			                                                    HeaderToVal(header));
			}

		return true;
		%}

	# REQUEST FC=22
	function deliver_MaskWriteRegisterRequest(header: ModbusTCP_TransportHeader, message: MaskWriteRegisterRequest): bool
		%{
		if ( ::modbus_mask_write_register_request )
			{
			zeek::BifEvent::enqueue_modbus_mask_write_register_request(connection()->zeek_analyzer(),
			                                                     connection()->zeek_analyzer()->Conn(),
			                                                     HeaderToVal(header),
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
			zeek::BifEvent::enqueue_modbus_mask_write_register_response(connection()->zeek_analyzer(),
			                                                      connection()->zeek_analyzer()->Conn(),
			                                                      HeaderToVal(header),
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
			connection()->zeek_analyzer()->AnalyzerViolation(
			    zeek::util::fmt("invalid value for modbus read write multiple registers request write byte count %d", ${message.write_byte_count}));
			return false;
			}

		if ( ::modbus_read_write_multiple_registers_request )
			{
			auto t = zeek::make_intrusive<zeek::VectorVal>(zeek::BifType::Vector::ModbusRegisters);

			for ( unsigned int i = 0; i < ${message.write_register_values}->size(); ++i )
				{
				auto r = zeek::val_mgr->Count(${message.write_register_values[i]});
				t->Assign(i, r);
				}

			zeek::BifEvent::enqueue_modbus_read_write_multiple_registers_request(connection()->zeek_analyzer(),
			                                                               connection()->zeek_analyzer()->Conn(),
			                                                               HeaderToVal(header),
			                                                               ${message.read_start_address},
			                                                               ${message.read_quantity},
			                                                               ${message.write_start_address},
			                                                               std::move(t));
			}

		return true;
		%}

	# RESPONSE FC=23
	function deliver_ReadWriteMultipleRegistersResponse(header: ModbusTCP_TransportHeader, message: ReadWriteMultipleRegistersResponse): bool
		%{
		if ( ${message.byte_count} % 2 != 0 )
			{
			connection()->zeek_analyzer()->AnalyzerViolation(
			    zeek::util::fmt("invalid value for modbus read write multiple registers response byte count %d", ${message.byte_count}));
			return false;
			}

		if ( ::modbus_read_write_multiple_registers_response )
			{
			auto t = zeek::make_intrusive<zeek::VectorVal>(zeek::BifType::Vector::ModbusRegisters);

			for ( unsigned int i = 0; i < ${message.registers}->size(); ++i )
				{
				auto r = zeek::val_mgr->Count(${message.registers[i]});
				t->Assign(i, r);
				}

			zeek::BifEvent::enqueue_modbus_read_write_multiple_registers_response(connection()->zeek_analyzer(),
			                                                                connection()->zeek_analyzer()->Conn(),
			                                                                HeaderToVal(header),
			                                                                std::move(t));
			}

		return true;
		%}

	# REQUEST FC=24
	function deliver_ReadFIFOQueueRequest(header: ModbusTCP_TransportHeader, message: ReadFIFOQueueRequest): bool
		%{
		if ( ::modbus_read_fifo_queue_request )
			{
			zeek::BifEvent::enqueue_modbus_read_fifo_queue_request(connection()->zeek_analyzer(),
			                                                 connection()->zeek_analyzer()->Conn(),
			                                                 HeaderToVal(header),
			                                                 ${message.start_address});
			}

		return true;
		%}


	# RESPONSE FC=24
	function deliver_ReadFIFOQueueResponse(header: ModbusTCP_TransportHeader, message: ReadFIFOQueueResponse): bool
		%{
		if ( ${message.byte_count} % 2 != 0 )
			{
			connection()->zeek_analyzer()->AnalyzerViolation(
			    zeek::util::fmt("invalid value for modbus read FIFO queue response byte count %d", ${message.byte_count}));
			return false;
			}

		if ( ::modbus_read_fifo_queue_response )
			{
			auto t = create_vector_of_count();

			for ( unsigned int i = 0; i < (${message.register_data})->size(); ++i )
				{
				auto r = zeek::val_mgr->Count(${message.register_data[i]});
				t->Assign(i, r);
				}

			zeek::BifEvent::enqueue_modbus_read_fifo_queue_response(connection()->zeek_analyzer(),
			                                                  connection()->zeek_analyzer()->Conn(),
			                                                  HeaderToVal(header),
			                                                  std::move(t));
			}

		return true;
		%}
};
