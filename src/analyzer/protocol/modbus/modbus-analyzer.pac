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
		modbus_header->Assign(4, header->len());
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
	function deliver_Exception(header: ModbusTCP_TransportHeader, message: ModbusTCP_ExceptResponse): bool
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


	# REQUEST FC=8
	function deliver_DiagnosticsRequest(header: ModbusTCP_TransportHeader, message: DiagnosticsRequest): bool
		%{
		if ( ::modbus_diagnostics_request )
			{
			auto data = to_stringval(${message.data});

			// Data should always be a multiple of two bytes. For everything except
			// "Return Query Data (0x00)" it should be two bytes long.
			if ( data->Len() < 2 || data->Len() % 2 != 0 ||
			     (${message.subfunction} != DIAGNOSTICS_RETURN_QUERY_DATA && data->Len() != 2) )
				{
				zeek::reporter->Weird("modbus_diag_invalid_request_data",
				                      zeek::util::fmt("%s", data->CheckString()));
				return false;
				}

			switch (${message.subfunction})
				{
				case DIAGNOSTICS_RESTART_COMMUNICATIONS_OPTION:
					// For "Restart Communications Option" it's either 0x0000 or 0xFF00.
					if ( ( data->Bytes()[0] != 0x00 && data->Bytes()[0] != 0xFF ) ||
					     data->Bytes()[1] != 0x00 )
						{
						zeek::reporter->Weird("modbus_diag_invalid_request_data",
						                      zeek::util::fmt("%s", data->CheckString()));
						}
					break;
				case DIAGNOSTICS_RETURN_DIAGNOSTIC_REGISTER:
				case DIAGNOSTICS_FORCE_LISTEN_ONLY_MODE:
				case DIAGNOSTICS_CLEAR_COUNTERS_AND_DIAGNOSTIC_REGISTER:
				case DIAGNOSTICS_RETURN_BUS_MESSAGE_COUNT:
				case DIAGNOSTICS_RETURN_BUS_COMMUNICATION_ERROR_COUNT:
				case DIAGNOSTICS_RETURN_BUS_EXCEPTION_ERROR_COUNT:
				case DIAGNOSTICS_RETURN_SERVER_MESSAGE_COUNT:
				case DIAGNOSTICS_RETURN_SERVER_NO_RESPONSE_COUNT:
				case DIAGNOSTICS_RETURN_SERVER_NAK_COUNT:
				case DIAGNOSTICS_RETURN_SERVER_BUSY_COUNT:
				case DIAGNOSTICS_RETURN_BUS_CHARACTER_OVERRUN_COUNT:
				case DIAGNOSTICS_CLEAR_OVERRUN_COUNTER_AND_FLAG:
					// For all of these subfunctions, the data should be 0x0000.
					if ( data->Bytes()[0] != 0x00 || data->Bytes()[1] != 0x00 )
						{
						zeek::reporter->Weird("modbus_diag_invalid_request_data",
						                      zeek::util::fmt("%s", data->CheckString()));
						}
					break;

				case DIAGNOSTICS_CHANGE_ASCII_INPUT_DELIMITER:
					// For "Change ASCII Input Delimiter", it should be an ascii character
					// followed by a zero.
					if ( ! isascii(data->Bytes()[0]) || data->Bytes()[1] != 0x00 )
						{
						zeek::reporter->Weird("modbus_diag_invalid_request_data",
						                      zeek::util::fmt("%s", data->CheckString()));
						}
					break;

				default:
					zeek::reporter->Weird("modbus_diag_unknown_request_subfunction",
					                      zeek::util::fmt("%d", ${message.subfunction}));
					break;
				}

			zeek::BifEvent::enqueue_modbus_diagnostics_request(connection()->zeek_analyzer(),
			                                                   connection()->zeek_analyzer()->Conn(),
			                                                   HeaderToVal(header),
			                                                   ${message.subfunction}, to_stringval(${message.data}));
			}

		return true;
		%}

	# RESPONSE FC=8
	function deliver_DiagnosticsResponse(header: ModbusTCP_TransportHeader, message: DiagnosticsResponse): bool
		%{
		if ( ::modbus_diagnostics_response )
			{
			zeek::BifEvent::enqueue_modbus_diagnostics_response(connection()->zeek_analyzer(),
			                                                    connection()->zeek_analyzer()->Conn(),
			                                                    HeaderToVal(header),
			                                                    ${message.subfunction}, to_stringval(${message.data}));
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
			auto vect = zeek::make_intrusive<zeek::VectorVal>(zeek::BifType::Vector::ModbusFileRecordRequests);

			for ( const auto& ref : *(${message.references}) )
				{
				auto r = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::ModbusFileRecordRequest);

				r->Assign(0, zeek::val_mgr->Count(${ref.ref_type}));
				r->Assign(1, zeek::val_mgr->Count(${ref.file_num}));
				r->Assign(2, zeek::val_mgr->Count(${ref.record_num}));
				r->Assign(3, zeek::val_mgr->Count(${ref.record_len}));

				vect->Append(r);
				}

			zeek::BifEvent::enqueue_modbus_read_file_record_request(connection()->zeek_analyzer(),
			                                                connection()->zeek_analyzer()->Conn(),
			                                                HeaderToVal(header), ${message.byte_count}, vect);
			}

		return true;
		%}

	# RESPONSE FC=20
	function deliver_ReadFileRecordResponse(header: ModbusTCP_TransportHeader, message: ReadFileRecordResponse): bool
		%{
		if ( ::modbus_read_file_record_response )
			{
			auto vect = zeek::make_intrusive<zeek::VectorVal>(zeek::BifType::Vector::ModbusFileRecordResponses);

			for ( const auto& ref : *(${message.references}) )
				{
				auto r = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::ModbusFileRecordResponse);

				r->Assign(0, zeek::val_mgr->Count(${ref.file_len}));
				r->Assign(1, zeek::val_mgr->Count(${ref.ref_type}));
				r->Assign(2, to_stringval(${ref.record_data}));

				vect->Append(r);
				}

			zeek::BifEvent::enqueue_modbus_read_file_record_response(connection()->zeek_analyzer(),
			                                                   connection()->zeek_analyzer()->Conn(),
			                                                   HeaderToVal(header), ${message.byte_count}, vect);
			}

		return true;
		%}

	# REQUEST FC=21
	function deliver_WriteFileRecordRequest(header: ModbusTCP_TransportHeader, message: WriteFileRecordRequest): bool
		%{
		if ( ::modbus_write_file_record_request )
			{
			auto vect = zeek::make_intrusive<zeek::VectorVal>(zeek::BifType::Vector::ModbusFileReferences);

			for ( const auto& ref : *(${message.references}) )
				{
				auto r = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::ModbusFileReference);
				r->Assign(0, zeek::val_mgr->Count(${ref.ref_type}));
				r->Assign(1, zeek::val_mgr->Count(${ref.file_num}));
				r->Assign(2, zeek::val_mgr->Count(${ref.record_num}));
				r->Assign(3, zeek::val_mgr->Count(${ref.record_length}));
				r->Assign(4, to_stringval(${ref.record_data}));

				vect->Append(r);
				}

			zeek::BifEvent::enqueue_modbus_write_file_record_request(connection()->zeek_analyzer(),
			                                                   connection()->zeek_analyzer()->Conn(),
			                                                   HeaderToVal(header), ${message.byte_count}, vect);
			}

		return true;
		%}

	# RESPONSE FC=21
	function deliver_WriteFileRecordResponse(header: ModbusTCP_TransportHeader, message: WriteFileRecordResponse): bool
		%{
		if ( ::modbus_write_file_record_response )
			{
			auto vect = zeek::make_intrusive<zeek::VectorVal>(zeek::BifType::Vector::ModbusFileReferences);

			for ( const auto& ref : *(${message.references}) )
				{
				auto r = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::ModbusFileReference);
				r->Assign(0, zeek::val_mgr->Count(${ref.ref_type}));
				r->Assign(1, zeek::val_mgr->Count(${ref.file_num}));
				r->Assign(2, zeek::val_mgr->Count(${ref.record_num}));
				r->Assign(3, zeek::val_mgr->Count(${ref.record_length}));
				r->Assign(4, to_stringval(${ref.record_data}));

				vect->Append(r);
				}

			zeek::BifEvent::enqueue_modbus_write_file_record_response(connection()->zeek_analyzer(),
			                                                    connection()->zeek_analyzer()->Conn(),
			                                                    HeaderToVal(header), ${message.byte_count}, vect);
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

	# REQUEST FC=2B
	function deliver_EncapInterfaceTransportRequest(header: ModbusTCP_TransportHeader, message: EncapInterfaceTransportRequest): bool
		%{
		if ( ::modbus_encap_interface_transport_request )
			{
			zeek::BifEvent::enqueue_modbus_encap_interface_transport_request(
			    connection()->zeek_analyzer(), connection()->zeek_analyzer()->Conn(),
			    HeaderToVal(header), ${message.mei_type}, to_stringval(${message.data}));
			}

		return true;
		%}

	# RESPONSE FC=2B
	function deliver_EncapInterfaceTransportResponse(header: ModbusTCP_TransportHeader, message: EncapInterfaceTransportResponse): bool
		%{
		if ( ::modbus_encap_interface_transport_response )
			{
			zeek::BifEvent::enqueue_modbus_encap_interface_transport_response(
			    connection()->zeek_analyzer(), connection()->zeek_analyzer()->Conn(),
			    HeaderToVal(header), ${message.mei_type}, to_stringval(${message.data}));
			}

		return true;
		%}

};
