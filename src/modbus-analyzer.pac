#
# The development of Bro's Modbus analyzer has been made possible thanks to
# the support of the Ministry of Security and Justice of the Kingdom of the
# Netherlands within the projects of Hermes, Castor and Midas.
#
# Useful references: http://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf
#                    http://www.simplymodbus.ca/faq.htm
#

flow ModbusTCP_Flow(is_orig: bool)
{
	flowunit = ModbusTCP_PDU(is_orig) withcontext (connection, this);

	# Parse only headers for request and response.
	function deliver_message(tid: uint16, pid: uint16, uid: uint8, fc: uint8, flag: int): bool
		%{
		if ( flag == 1 )
			{
			if ( ::modbus_request )
				{
				BifEvent::generate_modbus_request(connection()->bro_analyzer(),
								  connection()->bro_analyzer()->Conn(),
								  is_orig(), tid, pid, uid, fc);
				}
			}

		else if ( flag == 2 )
			{
			if ( ::modbus_response )
				{
				BifEvent::generate_modbus_response(connection()->bro_analyzer(),
								   connection()->bro_analyzer()->Conn(),
								   is_orig(), tid, pid, uid, fc);
				}
			}

		return true;
		%}

	# REQUEST FC=1
	function deliver_ReadCoilsReq(tid: uint16, pid: uint16, uid: uint8, fc: uint8, ref: uint16, bitCount: uint16, len:uint16): bool
		%{
		if ( ::modbus_read_coils_request )
			{
			BifEvent::generate_modbus_read_coils_request(connection()->bro_analyzer(),
								     connection()->bro_analyzer()->Conn(),
								     is_orig(), tid, pid, uid, fc, len, ref, bitCount);
			}

		return true;
		%}

	# REQUEST FC=2
	function deliver_ReadInputDiscReq(tid: uint16, pid: uint16, uid: uint8, fc: uint8, ref: uint16, bitCount: uint16,len:uint16): bool
		%{
		if ( ::modbus_read_input_discretes_request )
			{
			BifEvent::generate_modbus_read_input_discretes_request(connection()->bro_analyzer(),
									       connection()->bro_analyzer()->Conn(),
									       is_orig(), tid, pid, uid, fc,len, ref, bitCount);
			}

		return true;
		%}

	# REQUEST FC=3
	function deliver_ReadMultiRegReq(tid: uint16, pid: uint16, uid: uint8, fc: uint8, ref: uint16, wcount: uint16, flag: uint16, len: uint16): bool
		%{
		if ( ::modbus_read_multi_request )
			{
			BifEvent::generate_modbus_read_multi_request(connection()->bro_analyzer(),
								     connection()->bro_analyzer()->Conn(),
								     is_orig(), tid, pid, uid, fc, len, ref, wcount);
			}

		return true;
		%}

	# REQUEST FC=4
	function deliver_ReadInputRegReq(tid: uint16, pid: uint16, uid: uint8, fc: uint8, ref: uint16, wcount: uint16, flag: uint16, len: uint16): bool
		%{
		if ( ::modbus_read_input_request )
			{
			BifEvent::generate_modbus_read_input_request(connection()->bro_analyzer(),
								     connection()->bro_analyzer()->Conn(),
								     is_orig(), tid, pid, uid, fc, len, ref, wcount);
			}

		return true;
		%}

	# REQUEST FC=5
	function deliver_WriteCoilReq(tid: uint16, pid: uint16, uid: uint8, fc: uint8, ref: uint16, onOff: uint8, other: uint8, len:uint16): bool
		%{
		if ( ::modbus_write_coil_request )
			{
			BifEvent::generate_modbus_write_coil_request(connection()->bro_analyzer(),
								     connection()->bro_analyzer()->Conn(),
								     is_orig(), tid, pid, uid, fc, len, ref, onOff, other);
			}

		return true;
		%}

	# REQUEST FC=6
	function deliver_WriteSingleRegReq(tid: uint16, pid: uint16, uid: uint8, fc: uint8, ref: uint16, value: uint16, len:uint16): bool
		%{
		if ( ::modbus_write_single_request )
			{
			BifEvent::generate_modbus_write_single_request(connection()->bro_analyzer(),
								       connection()->bro_analyzer()->Conn(),
								       is_orig(), tid, pid, uid, fc, len, ref, value);
			}

		return true;
		%}

	# REQUEST FC=15
	function deliver_ForceMultiCoilsReq(tid: uint16, pid: uint16, uid: uint8, fc: uint8, ref: uint16, bitCount: uint16, byteCount: uint16, coils: bytestring, len:uint16): bool
		%{
		if ( ::modbus_force_coils_request )
			{
			BifEvent::generate_modbus_force_coils_request(connection()->bro_analyzer(),
								      connection()->bro_analyzer()->Conn(),
								      is_orig(), tid, pid, uid, fc, len, ref, bitCount, byteCount, new StringVal(coils.length(), (const char*) coils.data()));
			}

		return true;
		%}

	# REQUEST FC=16
	function deliver_WriteMultiRegReq( writeMulti: WriteMultipleRegistersRequest, tid: uint16, pid: uint16, uid: uint8, fc: uint8, len: uint16): bool
		%{
		VectorVal * t = new VectorVal( new VectorType(base_type(TYPE_INT)));

		for ( unsigned int i = 0; i < (${writeMulti.registers}->size()); ++i )
			{
			Val* r = new Val(((*writeMulti->registers())[i]), TYPE_INT);
			t->Assign(i, r, 0, OP_ASSIGN);
			}

		if ( ::modbus_write_multi_request )
			{
			BifEvent::generate_modbus_write_multi_request(connection()->bro_analyzer(),
								      connection()->bro_analyzer()->Conn(),
								      is_orig(), t, tid, pid, uid, fc, len, ${writeMulti.referenceNumber}, ${writeMulti.wordCount}, ${writeMulti.byteCount});
			}

		return true;
		%}

	# REQUEST FC=20
	function deliver_ReadReferenceReq(tid: uint16, pid: uint16, uid: uint8, fc: uint8, refCount: uint8, reference:Reference[], len:uint16): bool
		%{
		VectorVal *t = new VectorVal(new VectorType(base_type(TYPE_INT)));

		for ( unsigned int i = 0; i < (${reference}->size()); ++i )
			{
			Val* r = new Val((${reference[i].refType}), TYPE_INT);
			t->Assign(i, r, 0, OP_ASSIGN);

			Val* k = new Val((${reference[i].refNumber}), TYPE_INT);
			t->Assign(i, k, 0, OP_ASSIGN);

			Val* l = new Val((${reference[i].wordCount}), TYPE_INT);
			t->Assign(i, l, 0, OP_ASSIGN);
			}

		if ( ::modbus_read_reference_request )
			{
			BifEvent::generate_modbus_read_reference_request(connection()->bro_analyzer(),
									 connection()->bro_analyzer()->Conn(),
									 is_orig(), tid, pid, uid, fc, len, refCount, t);
			}

		return true;
		%}

	# REQUEST FC=20 (to read single reference)
	function deliver_ReadSingleReferenceReq(tid: uint16, pid: uint16, uid: uint8, fc: uint8, refType: uint8, refNumber: uint32, wordCount: uint16): bool
		%{
		if ( ::modbus_read_single_reference_request)
			{
			BifEvent::generate_modbus_read_single_reference_request(connection()->bro_analyzer(),
										connection()->bro_analyzer()->Conn(),
										is_orig(), tid, pid, uid, fc, refType, refNumber, wordCount);
			}

		return true;
		%}

	# RESPONSE FC=20 (to read single reference)
	function deliver_ReadSingleReferenceRes(tid: uint16, pid: uint16, uid: uint8, fc: uint8, byteCount: uint8, refType: uint8, ref:ReferenceResponse): bool
		%{
		VectorVal *t = new VectorVal(new VectorType(base_type(TYPE_INT)));

		for ( unsigned int i = 0; i < (${ref.registerValue}->size()); ++i )
			{
			Val* r = new Val(((*ref->registerValue())[i]), TYPE_INT);
			t->Assign(i, r, 0, OP_ASSIGN);
			}

		if ( ::modbus_read_single_reference_response )
			{
			BifEvent::generate_modbus_read_single_reference_response(connection()->bro_analyzer(),
										 connection()->bro_analyzer()->Conn(),
										 is_orig(), tid, pid, uid, fc, byteCount, refType, t);
			}

		return true;
		%}

	# REQUEST FC=21
	function deliver_WriteReferenceReq(tid: uint16, pid: uint16, uid: uint8, fc: uint8, byteCount: uint8, reference:ReferenceWithData[], len:uint16): bool
		%{
		VectorVal* t = new VectorVal(new VectorType(base_type(TYPE_INT)));

		for ( unsigned int i = 0; i < (${reference}->size()); ++i )
			{
			Val* r = new Val((${reference[i].refType}), TYPE_INT);
			t->Assign(i, r, 0, OP_ASSIGN);

			Val* k = new Val((${reference[i].refNumber}), TYPE_INT);
			t->Assign(i, k, 0, OP_ASSIGN);

			Val* n = new Val((${reference[i].wordCount}), TYPE_INT);
			t->Assign(i, n, 0, OP_ASSIGN);

			for ( unsigned int j = 0; j < (${reference[i].registerValue}->size()); ++j )
				{
				k = new Val((${reference[i].registerValue[j]}), TYPE_INT);
				t->Assign(i, k, 0, OP_ASSIGN);
				}
			}

		if ( ::modbus_write_reference_request )
			{
			BifEvent::generate_modbus_write_reference_request(connection()->bro_analyzer(),
									  connection()->bro_analyzer()->Conn(),
									  is_orig(), tid, pid, uid, fc, len,  byteCount, t);
			}

		return true;
		%}

	# RESPONSE FC=21 (to write single reference)
	function deliver_WriteSingleReference(tid: uint16, pid: uint16, uid: uint8, fc: uint8, refType: uint8, refNumber: uint32, wordCount: uint16, ref:ReferenceWithData): bool
		%{
		VectorVal* t = new VectorVal(new VectorType(base_type(TYPE_INT)));

		for ( unsigned int i = 0; i < (${ref.registerValue}->size()); ++i )
			{
			Val* r = new Val(((*ref->registerValue())[i]), TYPE_INT);
			t->Assign(i, r, 0, OP_ASSIGN);
			}

		if ( ::modbus_write_single_reference)
			{
			BifEvent::generate_modbus_write_single_reference(connection()->bro_analyzer(),
									 connection()->bro_analyzer()->Conn(),
									 is_orig(), tid, pid, uid, fc, refType, refNumber, wordCount, t);
			}

		return true;
		%}

	# REQUEST FC=22
	function deliver_MaskWriteRegReq(tid: uint16, pid: uint16, uid: uint8, fc: uint8, ref: uint16, andMask: uint16, orMask: uint16, len:uint16): bool
		%{
		if ( ::modbus_mask_write_request )
			{
			BifEvent::generate_modbus_mask_write_request(connection()->bro_analyzer(),
								     connection()->bro_analyzer()->Conn(),
								     is_orig(), tid, pid, uid, fc, len, ref, andMask, orMask);
			}

		return true;
		%}

	# REQUEST FC=23
	function deliver_ReadWriteRegReq(doMulti: ReadWriteRegistersRequest, tid: uint16, pid: uint16, uid: uint8, fc: uint16, len: uint16): bool
		%{
		VectorVal* t = new VectorVal(new VectorType(base_type(TYPE_INT)));

		for ( unsigned int i = 0; i < (${doMulti.registerValues})->size(); ++i )
			{
			Val* r = new Val(((*doMulti->registerValues())[i]), TYPE_INT);
			t->Assign(i, r, 0, OP_ASSIGN);
			}

		if ( ::modbus_read_write_request )
			{
			BifEvent::generate_modbus_read_write_request(connection()->bro_analyzer(),
								     connection()->bro_analyzer()->Conn(),
								     is_orig(), t, tid, pid, uid, fc, len, ${doMulti.referenceNumberRead}, ${doMulti.wordCountRead}, ${doMulti.referenceNumberWrite}, ${doMulti.wordCountWrite}, ${doMulti.byteCount});
			}

		return true;
		%}

	# REQUEST FC=24
	function deliver_ReadFIFOReq(tid: uint16, pid: uint16, uid: uint8, fc: uint8, ref: uint16, len:uint16): bool
		%{
		if ( ::modbus_read_FIFO_request )
			{
			BifEvent::generate_modbus_read_FIFO_request(connection()->bro_analyzer(),
								    connection()->bro_analyzer()->Conn(),
								    is_orig(), tid, pid, uid, fc, len, ref);
			}

		return true;
		%}

	# RESPONSE FC=1
	function deliver_ReadCoilsRes(tid: uint16, pid: uint16, uid: uint8, fc: uint8, bCount: uint8, bits: bytestring, len:uint16): bool
		%{
		if ( ::modbus_read_coils_response )
			{
			BifEvent::generate_modbus_read_coils_response(connection()->bro_analyzer(),
								      connection()->bro_analyzer()->Conn(),
								      is_orig(), tid, pid, uid, fc, len, bCount, new StringVal(bits.length(), (const char*) bits.data()));
			}

		return true;
		%}

	# RESPONSE FC=2
	function deliver_ReadInputDiscRes(tid: uint16, pid: uint16, uid: uint8, fc: uint8, bCount: uint8, bits: bytestring, len:uint16): bool
		%{
		if ( ::modbus_read_input_discretes_response )
			{
			BifEvent::generate_modbus_read_input_discretes_response(connection()->bro_analyzer(),
										connection()->bro_analyzer()->Conn(),
										is_orig(), tid, pid, uid, fc,len, bCount, new StringVal(bits.length(), (const char*) bits.data()));
			}

		return true;
		%}

	# RESPONSE FC=3
	function deliver_ReadMultiRegRes( doMulti: ReadMultipleRegistersResponse, tid: uint16, pid: uint16, uid: uint8, fc: uint16, len: uint16): bool
		%{
		VectorVal* t = new VectorVal(new VectorType(base_type(TYPE_INT)));

		for ( unsigned int i = 0; i < (${doMulti.registers})->size(); ++i )
			{
			Val* r = new Val(((*doMulti->registers())[i]), TYPE_INT);
			t->Assign(i, r, 0, OP_ASSIGN);
			}

		if ( ::modbus_read_multi_response )
			{
			BifEvent::generate_modbus_read_multi_response(connection()->bro_analyzer(),
								      connection()->bro_analyzer()->Conn(),
								      is_orig(), t, tid, pid, uid, fc, len, ${doMulti.byteCount});
			}

		return true;
		%}

	# RESPONSE FC=4
	function deliver_ReadInputRegRes( doMulti: ReadInputRegistersResponse, tid: uint16, pid: uint16, uid: uint8, fc: uint16, len: uint16): bool
		%{
		VectorVal* t = new VectorVal(new VectorType(base_type(TYPE_INT)));

		for ( unsigned int i = 0; i < (${doMulti.registers})->size(); ++i )
			{
			Val* r = new Val(((*doMulti->registers())[i]), TYPE_INT);
			t->Assign(i, r, 0, OP_ASSIGN);
			}

		if ( ::modbus_read_input_response )
			{
			BifEvent::generate_modbus_read_input_response(connection()->bro_analyzer(),
								      connection()->bro_analyzer()->Conn(),
								      is_orig(), t, tid, pid, uid, fc, len, ${doMulti.byteCount});
			}

		return true;
		%}

	# RESPONSE FC=5
	function deliver_WriteCoilRes(tid: uint16, pid: uint16, uid: uint8, fc: uint8, ref: uint16, onOff: uint8, other: uint8,len:uint16): bool
		%{
		if ( ::modbus_write_coil_response )
			{
			BifEvent::generate_modbus_write_coil_response(connection()->bro_analyzer(),
								      connection()->bro_analyzer()->Conn(),
								      is_orig(), tid, pid, uid, fc, len, ref, onOff, other);
			}

		return true;
		%}

	# RESPONSE FC=6
	function deliver_WriteSingleRegRes(tid: uint16, pid: uint16, uid: uint8, fc: uint8, ref: uint16, value: uint16, len:uint16): bool
		%{
		if ( ::modbus_write_single_response)
			{
			BifEvent::generate_modbus_write_single_response(connection()->bro_analyzer(),
									connection()->bro_analyzer()->Conn(),
									is_orig(), tid, pid, uid, fc, len, ref, value);
			}

		return true;
		%}


	# RESPONSE FC=15
	function deliver_ForceMultiCoilsRes(tid: uint16, pid: uint16, uid: uint8, fc: uint8, ref: uint16, bitCount: uint16, len:uint16): bool
		%{
		if ( ::modbus_force_coils_response)
			{
			BifEvent::generate_modbus_force_coils_response(connection()->bro_analyzer(),
								       connection()->bro_analyzer()->Conn(),
								       is_orig(), tid, pid, uid, fc, len, ref, bitCount);
			}

		return true;
		%}

	# RESPONSE FC=16
	function deliver_WriteMultiRegRes(tid: uint16, pid: uint16, uid: uint8, fc: uint8, ref: uint16, wcount: uint16, len: uint16): bool
		%{
		if ( ::modbus_write_multi_response)
			{
			BifEvent::generate_modbus_write_multi_response(connection()->bro_analyzer(),
								       connection()->bro_analyzer()->Conn(),
								       is_orig(), tid, pid, uid, fc, len, ref, wcount);
			}

		return true;
		%}

	# RESPONSE FC=20
	function deliver_ReadReferenceRes(tid: uint16, pid: uint16, uid: uint8, fc: uint8, byteCount: uint8, reference:ReferenceResponse[], len:uint16): bool
		%{
		VectorVal* t = new VectorVal(new VectorType(base_type(TYPE_INT)));

		for ( unsigned int i = 0; i < (${reference}->size()); ++i )
			{
			Val* r = new Val((${reference[i].byteCount}), TYPE_INT);
			t->Assign(i, r, 0, OP_ASSIGN);

			Val* k = new Val((${reference[i].refType}), TYPE_INT);
			t->Assign(i, k, 0, OP_ASSIGN);

			for ( unsigned int j = 0; j<(${reference[i].registerValue}->size());++j)
				{
				k = new Val((${reference[i].registerValue[j]}), TYPE_INT);
				t->Assign(i, k, 0, OP_ASSIGN);
				}
			}

		if ( ::modbus_read_reference_response )
			{
			BifEvent::generate_modbus_read_reference_response(connection()->bro_analyzer(),
									  connection()->bro_analyzer()->Conn(),
									  is_orig(), tid, pid, uid, fc, len, byteCount, t);
			}
		return true;
		%}

	# RESPONSE FC=21
	function deliver_WriteReferenceRes(tid: uint16, pid: uint16, uid: uint8, fc: uint8, byteCount: uint8, reference:ReferenceWithData[],len:uint16): bool
		%{
		VectorVal* t = new VectorVal(new VectorType(base_type(TYPE_INT)));

		for ( unsigned int i = 0; i < (${reference}->size()); ++i )
			{
			Val* r = new Val((${reference[i].refType}), TYPE_INT);
			t->Assign(i, r, 0, OP_ASSIGN);

			Val* k = new Val((${reference[i].refNumber}), TYPE_INT);
			t->Assign(i, k, 0, OP_ASSIGN);

			Val* n = new Val((${reference[i].wordCount}), TYPE_INT);
			t->Assign(i, n, 0, OP_ASSIGN);

			for ( unsigned int j = 0; j<(${reference[i].registerValue}->size());++j)
				{
				k = new Val((${reference[i].registerValue[j]}), TYPE_INT);
				t->Assign(i, k, 0, OP_ASSIGN);
				}
			}

		if ( ::modbus_write_reference_response )
			{
			BifEvent::generate_modbus_write_reference_response(connection()->bro_analyzer(),
									   connection()->bro_analyzer()->Conn(),
									   is_orig(), tid, pid, uid, fc, len, byteCount, t);
			}

		return true;
		%}

	# RESPONSE FC=22
	function deliver_MaskWriteRegRes(tid: uint16, pid: uint16, uid: uint8, fc: uint8, ref: uint16, andMask: uint16, orMask: uint16, len:uint16): bool
		%{
		if ( ::modbus_mask_write_response )
			{
			BifEvent::generate_modbus_mask_write_response(connection()->bro_analyzer(),
								      connection()->bro_analyzer()->Conn(),
								      is_orig(), tid, pid, uid, fc, len, ref, andMask, orMask);
			}
		return true;
		%}

	# RESPONSE FC=23
	function deliver_ReadWriteRegRes(doMulti: ReadWriteRegistersResponse, tid: uint16, pid: uint16, uid: uint8, fc: uint16, len: uint16): bool
		%{
		VectorVal* t = new VectorVal(new VectorType(base_type(TYPE_INT)));

		for ( unsigned int i = 0; i < (${doMulti.registerValues})->size(); ++i )
			{
			Val* r = new Val(((*doMulti->registerValues())[i]), TYPE_INT);
			t->Assign(i, r, 0, OP_ASSIGN);
			}

		if ( ::modbus_read_write_response )
			{
			BifEvent::generate_modbus_read_write_response(connection()->bro_analyzer(),
								      connection()->bro_analyzer()->Conn(),
								      is_orig(), t, tid, pid, uid, fc, len, ${doMulti.byteCount});
			}

		return true;
		%}

	# RESPONSE FC=24
	function deliver_ReadFIFORes( doMulti: ReadFIFOQueueResponse, tid: uint16, pid: uint16, uid: uint8, fc: uint16, len:uint16): bool
		%{
		VectorVal* t = new VectorVal(new VectorType(base_type(TYPE_INT)));

		for ( unsigned int i = 0; i < (${doMulti.registerData})->size(); ++i )
			{
			Val* r = new Val(((*doMulti->registerData())[i]), TYPE_INT);
			t->Assign(i, r, 0, OP_ASSIGN);
			}

		if ( ::modbus_read_FIFO_response )
			{
			BifEvent::generate_modbus_read_FIFO_response(connection()->bro_analyzer(),
								     connection()->bro_analyzer()->Conn(),
								     is_orig(), t, tid, pid, uid, fc, len, ${doMulti.byteCount});
			}

		return true;
		%}

	# EXCEPTION
	function deliver_Exception(tid: uint16, pid: uint16, uid: uint8, fc: uint8, code: uint8): bool
		%{
		if ( ::modbus_exception)
			{
			BifEvent::generate_modbus_exception(connection()->bro_analyzer(),
							    connection()->bro_analyzer()->Conn(),
							    is_orig(), tid, pid, uid, fc, code);
			}

		return true;
		%}

	# REQUEST FC=7
	function deliver_ReadExceptStatReq(tid: uint16, pid: uint16, uid: uint8, fc: uint8, len: uint16): bool
		%{
		if ( ::modbus_read_except_request)
			{
			BifEvent::generate_modbus_read_except_request(connection()->bro_analyzer(),
								      connection()->bro_analyzer()->Conn(),
								      is_orig(), tid, pid, uid, fc, len);
			}

		return true;
		%}

	# RESPONSE FC=7
	function deliver_ReadExceptStatRes(tid: uint16, pid: uint16, uid: uint8, fc: uint8, status: uint8, len: uint16): bool
		%{
		if ( ::modbus_read_except_response)
			{
			BifEvent::generate_modbus_read_except_response(connection()->bro_analyzer(),
								       connection()->bro_analyzer()->Conn(),
								       is_orig(), tid, pid, uid, fc, status, len);
			}

		return true;
		%}
};



