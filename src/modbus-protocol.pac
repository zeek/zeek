

connection ModbusTCP_Conn() {
    upflow = ModbusTCP_Flow(true);
    downflow = ModbusTCP_Flow(false);
};

enum function_codes {
# Class 0
	READ_MULTIPLE_REGISTERS = 3,
	WRITE_MULTIPLE_REGISTERS = 16,
# Class 1
	READ_COILS = 1,
	READ_INPUT_DISCRETES = 2,
	READ_INPUT_REGISTERS = 4,
	WRITE_COIL = 5,
	WRITE_SINGLE_REGISTER = 6,
	READ_EXCEPTION_STATUS = 7,
# Class 2
	FORCE_MULTIPLE_COILS = 15,
	READ_GENERAL_REFERENCE = 20,
	WRITE_GENERAL_REFERENCE = 21,
	MASK_WRITE_REGISTER = 22,
	READ_WRITE_REGISTERS = 23,
	READ_FIFO_QUEUE = 24,
# Machine/vendor/network specific functions
	DIAGNOSTICS = 8,
	PROGRAM_484 = 9,
	POLL_484 = 10,
	GET_COMM_EVENT_COUNTERS = 11,
	GET_COMM_EVENT_LOG = 12,
	PROGRAM_584_984 = 13,
	POLL_584_984 = 14,
	REPORT_SLAVE = 17,
	PROGRAM_884_U84 = 18,
	RESET_COMM_LINK_884_U84 = 19,
	PROGRAM_CONCEPT = 40,
	FIRMWARE_REPLACEMENT = 125,
	PROGRAM_584_984_2 = 126,
	REPORT_LOCAL_ADDRESS = 127,
# Exceptions
	READ_MULTIPLE_REGISTERS_EXCEPTION = 0x83,
	WRITE_MULTIPLE_REGISTERS_EXCEPTION = 0x90,
	READ_COILS_EXCEPTION = 0x81,
	READ_INPUT_DISCRETES_EXCEPTION = 0x82,
	READ_INPUT_REGISTERS_EXCEPTION = 0x84,
	WRITE_COIL_EXCEPTION = 0x85,
	WRITE_SINGLE_REGISTER_EXCEPTION = 0x86,
	READ_EXCEPTION_STATUS_EXCEPTION = 0x87,
	FORCE_MULTIPLE_COILS_EXCEPTION = 0x8F,
	READ_GENERAL_REFERENCE_EXCEPTION = 0x94,
	WRITE_GENERAL_REFERENCE_EXCEPTION = 0x95,
	MASK_WRITE_REGISTER_EXCEPTION = 0x96,
	READ_WRITE_REGISTERS_EXCEPTION = 0x97,
	READ_FIFO_QUEUE_EXCEPTION = 0x98,
};

#
# Main Modbus/TCP PDU
#
type ModbusTCP_PDU(is_orig: bool) = case is_orig of {
	true  -> request:  ModbusTCP_RequestPDU;
	false -> response: ModbusTCP_ResponsePDU;
} &byteorder=bigendian;

type ModbusTCP_TransportHeader = record {
	tid: uint16;				# Transaction identifier
	pid: uint16;				# Protocol identifier
	len: uint16; 				# Length of everyting after this field
	uid: uint8;					# Unit identifier (previously 'slave address')
	fc: uint8; 					# MODBUS function code (see function_codes enum)
};

type Reference = record {
	refType: uint8;
	refNumber: uint32;
	wordCount: uint16;
};

type ReferenceWithData = record {
	refType: uint8;
	refNumber: uint32;
	wordCount: uint16;
	registerValue: uint16[wordCount] &length = 2*wordCount; # TODO: check that the array length is calculated correctly
};

type Exception(len: uint16) = record {
	code: uint8;
};

#
# Requests
#
type ModbusTCP_RequestPDU = record {
    header: ModbusTCP_TransportHeader;
    data: case header.fc of {
    	# Class 0
		READ_MULTIPLE_REGISTERS -> readMultipleRegisters: ReadMultipleRegistersRequest(header.len-2);
		WRITE_MULTIPLE_REGISTERS -> writeMultipleRegisters: WriteMultipleRegistersRequest(header.len-2);
		# Class 1
		READ_COILS -> readCoils: ReadCoilsRequest(header.len-2);
		READ_INPUT_DISCRETES -> readInputDiscretes: ReadInputDiscretesRequest(header.len-2);
		READ_INPUT_REGISTERS -> readInputRegisters: ReadInputRegistersRequest(header.len-2);
		WRITE_COIL -> writeCoil: WriteCoilRequest(header.len-2);
		WRITE_SINGLE_REGISTER -> writeSingleRegister: WriteSingleRegisterRequest(header.len-2);
		READ_EXCEPTION_STATUS -> readExceptionStatus: ReadExceptionStatusRequest(header.len-2);
		# Class 2
		FORCE_MULTIPLE_COILS -> forceMultipleCoils: ForceMultipleCoilsRequest(header.len-2);
		READ_GENERAL_REFERENCE -> readGeneralReference: ReadGeneralReferenceRequest(header.len-2);
		WRITE_GENERAL_REFERENCE -> writeGeneralReference: WriteGeneralReferenceRequest(header.len-2);
		MASK_WRITE_REGISTER -> maskWriteRegister: MaskWriteRegisterRequest(header.len-2);
		READ_WRITE_REGISTERS -> readWriteRegisters: ReadWriteRegistersRequest(header.len-2);
		READ_FIFO_QUEUE -> readFIFOQueue: ReadFIFOQueueRequest(header.len-2);
		# All the rest
		default -> unknown: bytestring &restofdata;
	};
} &length = (header.len+6);

# Class 0 requests

type ReadMultipleRegistersRequest(len: uint16) = record {
	referenceNumber: uint16;
	wordCount: uint16 &check(wordCount <= 125);
};

type WriteMultipleRegistersRequest(len: uint16) = record {
	referenceNumber: uint16;
	wordCount: uint16 &check(wordCount <= 100);
	byteCount: uint8;
	registers: uint16[wordCount] &length = byteCount;
};

# Class 1 requests

type ReadCoilsRequest(len: uint16) = record {
	referenceNumber: uint16;
	bitCount: uint16 &check(bitCount <= 2000);
};

type ReadInputDiscretesRequest(len: uint16) = record {
	referenceNumber: uint16;
	bitCount: uint16 &check(bitCount <= 2000);
};

type ReadInputRegistersRequest(len: uint16) = record {
	referenceNumber: uint16;
	wordCount: uint16 &check(wordCount <= 125);
};

type WriteCoilRequest(len: uint16) = record {
	referenceNumber: uint16;
	onOff: uint8 &check(onOff == 0x00 || onOff == 0xFF);
	other: uint8 &check(other == 0x00);
};

type WriteSingleRegisterRequest(len: uint16) = record {
	referenceNumber: uint16;
	registerValue: uint16;
};

type ReadExceptionStatusRequest(len: uint16) = record {
};

# Class 2 requests

type ForceMultipleCoilsRequest(len: uint16) = record {
	referenceNumber: uint16;
	bitCount: uint16 &check(bitCount <= 800);
	byteCount: uint8 &check(byteCount == (bitCount + 7)/8);
	coils: bytestring &length = byteCount;
};

type ReadGeneralReferenceRequest(len: uint16) = record {
	byteCount: uint8;
	references: Reference[referenceCount] &length = byteCount;
} &let {
	referenceCount: uint8 = byteCount/7;
};

type WriteGeneralReferenceRequest(len: uint16) = record {
	byteCount: uint8;
	references: ReferenceWithData[] &until($input.length() == 0) &length = byteCount;
} &length = len;

type MaskWriteRegisterRequest(len: uint16) = record {
	referenceNumber: uint16;
	andMask: uint16;
	orMask: uint16;
};

type ReadWriteRegistersRequest(len: uint16) = record {
	referenceNumberRead: uint16;
	wordCountRead: uint16 &check(wordCountRead <= 125);
	referenceNumberWrite: uint16;
	wordCountWrite: uint16 &check(wordCountWrite <= 100);
	byteCount: uint8 &check(byteCount == 2*wordCountWrite);
	registerValues: uint16[registerCount] &length = byteCount;
} &length = len, &let{
	registerCount : uint8 = byteCount / 2;
};

type ReadFIFOQueueRequest(len: uint16) = record {
	referenceNumber: uint16;
};

#
# Responses
#
type ModbusTCP_ResponsePDU = record {
    header: ModbusTCP_TransportHeader;
    data:  case header.fc of {
    	# Class 0
    	READ_MULTIPLE_REGISTERS -> readMultipleRegisters: ReadMultipleRegistersResponse(header.len-2);
        WRITE_MULTIPLE_REGISTERS -> writeMultipleRegisters: WriteMultipleRegistersResponse(header.len-2);
        # Class 1
        READ_COILS -> readCoils: ReadCoilsResponse(header.len-2);
        READ_INPUT_DISCRETES -> readInputDiscretes: ReadInputDiscretesResponse(header.len-2);
        READ_INPUT_REGISTERS -> readInputRegisters: ReadInputRegistersResponse(header.len-2);
        WRITE_COIL -> writeCoil: WriteCoilResponse(header.len-2);
        WRITE_SINGLE_REGISTER -> writeSingleRegister: WriteSingleRegisterResponse(header.len-2);
        READ_EXCEPTION_STATUS -> readExceptionStatus: ReadExceptionStatusResponse(header.len-2);
        # Class 2
        FORCE_MULTIPLE_COILS -> forceMultipleCoils: ForceMultipleCoilsResponse(header.len-2);
        READ_GENERAL_REFERENCE -> readGeneralReference: ReadGeneralReferenceResponse(header.len-2);
        WRITE_GENERAL_REFERENCE -> writeGeneralReference: WriteGeneralReferenceResponse(header.len-2);
        MASK_WRITE_REGISTER -> maskWriteRegister: MaskWriteRegisterResponse(header.len-2);
        READ_WRITE_REGISTERS -> readWriteRegisters: ReadWriteRegistersResponse(header.len-2);
        READ_FIFO_QUEUE -> readFIFOQueue: ReadFIFOQueueResponse(header.len-2);
        # Exceptions
        READ_MULTIPLE_REGISTERS_EXCEPTION -> readMultipleRegistersException : Exception(header.len-2);
		WRITE_MULTIPLE_REGISTERS_EXCEPTION -> writeMultipleRegistersException: Exception(header.len-2);
		READ_COILS_EXCEPTION -> readCoilsException: Exception(header.len-2);
		READ_INPUT_DISCRETES_EXCEPTION -> readInputDiscretesException: Exception(header.len-2);
		READ_INPUT_REGISTERS_EXCEPTION -> readInputRegistersException: Exception(header.len-2);
		WRITE_COIL_EXCEPTION -> writeCoilException: Exception(header.len-2);
		WRITE_SINGLE_REGISTER_EXCEPTION -> writeSingleRegisterException: Exception(header.len-2);
		READ_EXCEPTION_STATUS_EXCEPTION -> readExceptionStatusException: Exception(header.len-2);
		FORCE_MULTIPLE_COILS_EXCEPTION -> forceMultipleCoilsException: Exception(header.len-2);
		READ_GENERAL_REFERENCE_EXCEPTION -> readGeneralReferenceException: Exception(header.len-2);
		WRITE_GENERAL_REFERENCE_EXCEPTION -> writeGeneralReferenceException: Exception(header.len-2);
		MASK_WRITE_REGISTER_EXCEPTION -> maskWriteRegisterException: Exception(header.len-2);
		READ_WRITE_REGISTERS_EXCEPTION -> readWriteRegistersException: Exception(header.len-2);
		READ_FIFO_QUEUE_EXCEPTION -> readFIFOQueueException: Exception(header.len-2);
		# All the rest
        default -> unknown: bytestring &restofdata;
    };
} &length = (header.len+6);

# Class 0 responses

type ReadMultipleRegistersResponse(len: uint16) = record {
	byteCount: uint8;
	registers: uint16[registerCount] &length = byteCount;
} &let{
	registerCount : uint8 = byteCount/2;
};

type WriteMultipleRegistersResponse(len: uint16) = record {
	referenceNumber: uint16;
	wordCount: uint16;
};

# Class 1 responses

type ReadCoilsResponse(len: uint16) = record {
	byteCount: uint8;
	bits: bytestring &length = byteCount;
};

type ReadInputDiscretesResponse(len: uint16) = record {
	byteCount: uint8;
	bits: bytestring &length = byteCount;
};

type ReadInputRegistersResponse(len: uint16) = record {
	byteCount: uint8;
	registers: uint16[registerCount] &length = byteCount;
} &let {
	registerCount = byteCount/2;
};

type WriteCoilResponse(len: uint16) = record {
	referenceNumber: uint16;
	onOff: uint8 &check(onOff == 0x00 || onOff == 0xFF);
	other: uint8 &check(other == 0x00);
}

type WriteSingleRegisterResponse(len: uint16) = record {
	referenceNumber: uint16;
	registerValue: uint16;
};

type ReadExceptionStatusResponse(len: uint16) = record {
	status: uint8;
};

# Class 2 responses

type ForceMultipleCoilsResponse(len: uint16) = record {
	referenceNumber: uint16;
	bitCount: uint16;
};

type ReadGeneralReferenceResponse(len: uint16) = record {
	byteCount: uint8;
	references: bytestring &length = byteCount;
} &length = len;

type WriteGeneralReferenceResponse(len: uint16) = record {
	byteCount: uint8;
	references: ReferenceWithData[] &until($input.length() == 0) &length = byteCount;
} &length = len;

type MaskWriteRegisterResponse(len: uint16) = record {
	referenceNumber: uint16;
	andMask: uint16;
	orMask: uint16;
};

type ReadWriteRegistersResponse(len: uint16) = record {
	byteCount: uint8;
	registerValues: uint16[registerCount] &length = byteCount;
} &length = len, &let {
	registerCount = byteCount / 2;
};

type ReadFIFOQueueResponse(len: uint16) = record {
	byteCount: uint16 &check(byteCount <= 64);
	wordCount: uint16 &check(wordCount <= 31);
	registerData: uint16[wordCount] &length = byteCount; 
} &length = len;

