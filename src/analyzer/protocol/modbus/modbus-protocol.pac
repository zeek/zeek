#
# The development of Zeek's Modbus analyzer has been made possible thanks to
# the support of the Ministry of Security and Justice of the Kingdom of the
# Netherlands within the projects of Hermes, Castor and Midas.
#
# Useful references: http://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf
#                    http://www.simplymodbus.ca/faq.htm

enum function_codes {
	# Standard functions
	READ_COILS                    = 0x01,
	READ_DISCRETE_INPUTS          = 0x02,
	READ_HOLDING_REGISTERS        = 0x03,
	READ_INPUT_REGISTERS          = 0x04,
	WRITE_SINGLE_COIL             = 0x05,
	WRITE_SINGLE_REGISTER         = 0x06,
	# READ_EXCEPTION_STATUS         = 0x07,
	# DIAGNOSTICS                   = 0x08,
	# GET_COMM_EVENT_COUNTER        = 0x0B,
	# GET_COMM_EVENT_LOG            = 0x0C,
	WRITE_MULTIPLE_COILS          = 0x0F,
	WRITE_MULTIPLE_REGISTERS      = 0x10,
	# REPORT_SLAVE_ID               = 0x11,
	READ_FILE_RECORD              = 0x14,
	WRITE_FILE_RECORD             = 0x15,
	MASK_WRITE_REGISTER           = 0x16,
	READ_WRITE_MULTIPLE_REGISTERS = 0x17,
	READ_FIFO_QUEUE               = 0x18,
	ENCAP_INTERFACE_TRANSPORT     = 0x2B,

	# Machine/vendor/network specific functions
	PROGRAM_484                   = 0x09,
	POLL_484                      = 0x0A,
	PROGRAM_584_984               = 0x0D,
	POLL_584_984                  = 0x0E,
	PROGRAM_884_U84               = 0x12,
	RESET_COMM_LINK_884_U84       = 0x13,
	PROGRAM_CONCEPT               = 0x28,
	FIRMWARE_REPLACEMENT          = 0x7D,
	PROGRAM_584_984_2             = 0x7E,
	REPORT_LOCAL_ADDRESS          = 0x7F,

	# Exceptions (not really function codes but they are used similarly)
	READ_COILS_EXCEPTION                    = 0x81,
	READ_DISCRETE_INPUTS_EXCEPTION          = 0x82,
	READ_HOLDING_REGISTERS_EXCEPTION        = 0x83,
	READ_INPUT_REGISTERS_EXCEPTION          = 0x84,
	WRITE_SINGLE_COIL_EXCEPTION             = 0x85,
	WRITE_SINGLE_REGISTER_EXCEPTION         = 0x86,
	READ_EXCEPTION_STATUS_EXCEPTION         = 0x87,
	WRITE_MULTIPLE_COILS_EXCEPTION          = 0x8F,
	WRITE_MULTIPLE_REGISTERS_EXCEPTION      = 0x90,
	READ_FILE_RECORD_EXCEPTION              = 0x94,
	WRITE_FILE_RECORD_EXCEPTION             = 0x95,
	MASK_WRITE_REGISTER_EXCEPTION           = 0x96,
	READ_WRITE_MULTIPLE_REGISTERS_EXCEPTION = 0x97,
	READ_FIFO_QUEUE_EXCEPTION               = 0x98,
};

# Main Modbus/TCP PDU
type ModbusTCP_PDU(is_orig: bool) = record {
	header: ModbusTCP_TransportHeader;
	body: case is_orig of {
		true  -> request:  ModbusTCP_Request(header);
		false -> response: ModbusTCP_Response(header);
	};
} &let {
	deliver: bool = $context.flow.deliver_ModbusTCP_PDU(this);
} &length=header.len+6, &byteorder=bigendian;

type ModbusTCP_TransportHeader = record {
	tid: uint16; # Transaction identifier
	pid: uint16; # Protocol identifier
	len: uint16; # Length of everything after this field
	uid: uint8;  # Unit identifier (previously 'slave address')
	fc:  uint8;  # MODBUS function code (see function_codes enum)
} &byteorder=bigendian, &let {
	deliver: bool = $context.flow.deliver_message(this);
};

type ModbusTCP_Request(header: ModbusTCP_TransportHeader) = case header.fc of {
	READ_COILS                    -> readCoils:                  ReadCoilsRequest(header);
	READ_DISCRETE_INPUTS          -> readDiscreteInputs:         ReadDiscreteInputsRequest(header);
	READ_HOLDING_REGISTERS        -> readHoldingRegisters:       ReadHoldingRegistersRequest(header);
	READ_INPUT_REGISTERS          -> readInputRegisters:         ReadInputRegistersRequest(header);
	WRITE_SINGLE_COIL             -> writeSingleCoil:            WriteSingleCoilRequest(header);
	WRITE_SINGLE_REGISTER         -> writeSingleRegister:        WriteSingleRegisterRequest(header);
	#READ_EXCEPTION_STATUS         -> readExceptionStatus:        ReadExceptionStatusRequest(header);
	#DIAGNOSTICS                   -> diagnostics:                DiagnosticsRequest(header);
	#GET_COMM_EVENT_COUNTER        -> getCommEventCounter:        GetCommEventCounterRequest(header);
	#GET_COMM_EVENT_LOG            -> getCommEventLog:            GetCommEventLogRequest(header);
	WRITE_MULTIPLE_COILS          -> writeMultipleCoils:         WriteMultipleCoilsRequest(header);
	WRITE_MULTIPLE_REGISTERS      -> writeMultRegisters:         WriteMultipleRegistersRequest(header);
	#REPORT_SLAVE_ID
	READ_FILE_RECORD              -> readFileRecord:             ReadFileRecordRequest(header);
	WRITE_FILE_RECORD             -> writeFileRecord:            WriteFileRecordRequest(header);
	MASK_WRITE_REGISTER           -> maskWriteRegister:          MaskWriteRegisterRequest(header);
	READ_WRITE_MULTIPLE_REGISTERS -> readWriteMultipleRegisters: ReadWriteMultipleRegistersRequest(header);
	READ_FIFO_QUEUE               -> readFIFOQueue:              ReadFIFOQueueRequest(header);
	#ENCAP_INTERFACE_TRANSPORT

	# All the rest
	default                       -> unknown:                    bytestring &restofdata;
};

# Responses
#
type ModbusTCP_Response(header: ModbusTCP_TransportHeader) = case header.fc of {
	READ_COILS                          -> readCoils:                       ReadCoilsResponse(header);
	READ_DISCRETE_INPUTS                -> readDiscreteInputs:              ReadDiscreteInputsResponse(header);
	READ_HOLDING_REGISTERS              -> readHoldingRegisters:            ReadHoldingRegistersResponse(header);
	READ_INPUT_REGISTERS                -> readInputRegisters:              ReadInputRegistersResponse(header);
	WRITE_SINGLE_COIL                   -> writeSingleCoil:                 WriteSingleCoilResponse(header);
	WRITE_SINGLE_REGISTER               -> writeSingleRegister:             WriteSingleRegisterResponse(header);
	#READ_EXCEPTION_STATUS               -> readExceptionStatus:             ReadExceptionStatusResponse(header);
	#DIAGNOSTICS                         -> diagnostics:                     DiagnosticsResponse(header);
	#GET_COMM_EVENT_COUNTER              -> getCommEventCounter:             GetCommEventCounterResponse(header);
	#GET_COMM_EVENT_LOG                  -> getCommEventLog:                 GetCommEventLogResponse(header);
	WRITE_MULTIPLE_COILS                -> writeMultipleCoils:              WriteMultipleCoilsResponse(header);
	WRITE_MULTIPLE_REGISTERS            -> writeMultRegisters:              WriteMultipleRegistersResponse(header);
	#REPORT_SLAVE_ID
	READ_FILE_RECORD                    -> readFileRecord:                  ReadFileRecordResponse(header);
	WRITE_FILE_RECORD                   -> writeFileRecord:                 WriteFileRecordResponse(header);
	MASK_WRITE_REGISTER                 -> maskWriteRegister:               MaskWriteRegisterResponse(header);
	READ_WRITE_MULTIPLE_REGISTERS       -> readWriteMultipleRegisters:      ReadWriteMultipleRegistersResponse(header);
	READ_FIFO_QUEUE                     -> readFIFOQueue:                   ReadFIFOQueueResponse(header);

	# Exceptions
	READ_HOLDING_REGISTERS_EXCEPTION        -> readHoldingRegistersException:   Exception(header);
	WRITE_MULTIPLE_REGISTERS_EXCEPTION      -> writeMultRegistersException:     Exception(header);
	READ_COILS_EXCEPTION                    -> readCoilsException:              Exception(header);
	READ_DISCRETE_INPUTS_EXCEPTION          -> readDiscreteInputsException:     Exception(header);
	READ_INPUT_REGISTERS_EXCEPTION          -> readInputRegistersException:     Exception(header);
	WRITE_SINGLE_COIL_EXCEPTION             -> writeCoilException:              Exception(header);
	WRITE_SINGLE_REGISTER_EXCEPTION         -> writeSingleRegisterException:    Exception(header);
	READ_EXCEPTION_STATUS_EXCEPTION         -> readExceptionStatusException:    Exception(header);
	WRITE_MULTIPLE_COILS_EXCEPTION          -> forceMultipleCoilsException:     Exception(header);
	READ_FILE_RECORD_EXCEPTION              -> readGeneralReferenceException:   Exception(header);
	WRITE_FILE_RECORD_EXCEPTION             -> writeGeneralReferenceException:  Exception(header);
	MASK_WRITE_REGISTER_EXCEPTION           -> maskWriteRegisterException:      Exception(header);
	READ_WRITE_MULTIPLE_REGISTERS_EXCEPTION -> readWriteRegistersException:     Exception(header);
	READ_FIFO_QUEUE_EXCEPTION               -> readFIFOQueueException:          Exception(header);

	# All the rest
	default                                 -> unknown:                         bytestring &restofdata;
};

type Exception(header: ModbusTCP_TransportHeader) = record {
	code: uint8;
} &let {
	deliver: bool = $context.flow.deliver_Exception(header, this);
};

# REQUEST FC=1
type ReadCoilsRequest(header: ModbusTCP_TransportHeader) = record {
	start_address:  uint16;
	quantity:       uint16; # &check(quantity <= 2000);
} &let {
	deliver: bool = $context.flow.deliver_ReadCoilsRequest(header, this);
} &byteorder=bigendian;

# RESPONSE FC=1
type ReadCoilsResponse(header: ModbusTCP_TransportHeader) = record {
	byte_count: uint8;
	bits:       bytestring &length=byte_count;
} &let {
	deliver: bool = $context.flow.deliver_ReadCoilsResponse(header, this);
} &byteorder=bigendian;

# REQUEST FC=2
type ReadDiscreteInputsRequest(header: ModbusTCP_TransportHeader) = record {
	start_address: uint16;
	quantity:      uint16; # &check(quantity <= 2000);
} &let {
	deliver: bool = $context.flow.deliver_ReadDiscreteInputsRequest(header, this);
} &byteorder=bigendian;

# RESPONSE FC=2
type ReadDiscreteInputsResponse(header: ModbusTCP_TransportHeader) = record {
	byte_count: uint8;
	bits:       bytestring &length=byte_count;
} &let {
	deliver: bool = $context.flow.deliver_ReadDiscreteInputsResponse(header, this);
} &byteorder=bigendian;

# REQUEST FC=3
type ReadHoldingRegistersRequest(header: ModbusTCP_TransportHeader) = record {
	start_address: uint16;
	quantity:      uint16; # &check(quantity <= 125);
} &let {
	deliver: bool = $context.flow.deliver_ReadHoldingRegistersRequest(header, this);
} &byteorder=bigendian;

# RESPONSE FC=3
type ReadHoldingRegistersResponse(header: ModbusTCP_TransportHeader) = record {
	byte_count: uint8;
	registers:  uint16[byte_count/2] &length=byte_count;
} &let {
	deliver: bool = $context.flow.deliver_ReadHoldingRegistersResponse(header, this);
} &byteorder=bigendian;

# REQUEST FC=4
type ReadInputRegistersRequest(header: ModbusTCP_TransportHeader) = record {
	start_address: uint16;
	quantity:      uint16; # &check(quantity <= 125);
} &let {
	deliver: bool = $context.flow.deliver_ReadInputRegistersRequest(header, this);
} &byteorder=bigendian;

# RESPONSE FC=4
type ReadInputRegistersResponse(header: ModbusTCP_TransportHeader) = record {
	byte_count: uint8;
	registers:  uint16[byte_count/2] &length=byte_count;
} &let {
	deliver: bool = $context.flow.deliver_ReadInputRegistersResponse(header, this);
} &byteorder=bigendian;

# REQUEST FC=5
type WriteSingleCoilRequest(header: ModbusTCP_TransportHeader) = record {
	address: uint16;
	value:   uint16; # &check(value == 0x0000 || value == 0xFF00);
} &let {
	deliver: bool = $context.flow.deliver_WriteSingleCoilRequest(header, this);
} &byteorder=bigendian;

# RESPONSE FC=5
type WriteSingleCoilResponse(header: ModbusTCP_TransportHeader) = record {
	address: uint16;
	value:   uint16; # &check(value == 0x0000 || value == 0xFF00);
} &let {
	deliver: bool = $context.flow.deliver_WriteSingleCoilResponse(header, this);
} &byteorder=bigendian;

# REQUEST FC=6
type WriteSingleRegisterRequest(header: ModbusTCP_TransportHeader) = record {
	address:  uint16;
	value:    uint16;
} &let {
	deliver: bool = $context.flow.deliver_WriteSingleRegisterRequest(header, this);
} &byteorder=bigendian;

# RESPONSE FC=6
type WriteSingleRegisterResponse(header: ModbusTCP_TransportHeader) = record {
	address:   uint16;
	value:     uint16;
} &let {
	deliver: bool = $context.flow.deliver_WriteSingleRegisterResponse(header, this);
} &byteorder=bigendian;

# REQUEST FC=15
type WriteMultipleCoilsRequest(header: ModbusTCP_TransportHeader) = record {
	start_address:    uint16;
	quantity:         uint16; #     &check(quantity <= 0x07B0);
	byte_count:       uint8; #      &check(byte_count == (quantity + 7)/8);
	coils:            bytestring &length=byte_count;
} &let {
	deliver: bool = $context.flow.deliver_WriteMultipleCoilsRequest(header, this);
} &byteorder=bigendian;

# RESPONSE FC=15
type WriteMultipleCoilsResponse(header: ModbusTCP_TransportHeader) = record {
	start_address:   uint16;
	quantity:        uint16; # &check(quantity <= 0x07B0);
} &let {
	deliver: bool = $context.flow.deliver_WriteMultipleCoilsResponse(header, this);
} &byteorder=bigendian;

# REQUEST FC=16
type WriteMultipleRegistersRequest(header: ModbusTCP_TransportHeader) = record {
	start_address: uint16;
	quantity:      uint16;
	byte_count:    uint8;
	# We specify registers buffer with quantity and byte_count so that the analyzer
	# will choke if something doesn't match right (correct devices should make it right).
	registers:     uint16[quantity] &length=byte_count;
} &let {
	deliver: bool = $context.flow.deliver_WriteMultipleRegistersRequest(header, this);
} &byteorder=bigendian;

# RESPONSE FC=16
type WriteMultipleRegistersResponse(header: ModbusTCP_TransportHeader) = record {
	start_address: uint16;
	quantity:      uint16;
} &let {
	deliver: bool = $context.flow.deliver_WriteMultipleRegistersResponse(header, this);
} &byteorder=bigendian;

# Support data structure for following message type.
type FileRecordRequest = record {
	ref_type:   uint8; #  &check(ref_type == 6);
	file_num:   uint16; # &check(file_num > 0);
	record_num: uint16; # &check(record_num <= 0x270F);
	record_len: uint16;
} &byteorder=bigendian;

# REQUEST FC=20
type ReadFileRecordRequest(header: ModbusTCP_TransportHeader) = record {
	byte_count: uint8; #               &check(byte_count <= 0xF5);
	references: FileRecordRequest[] &length=byte_count;
} &let {
	deliver: bool = $context.flow.deliver_ReadFileRecordRequest(header, this);
} &byteorder=bigendian;

# Support data structure for the following message type.
type FileRecordResponse = record {
	file_len:    uint8; #    &check(file_len >= 0x07 && file_len <= 0xF5);
	ref_type:    uint8; #    &check(ref_type == 6);
	record_data: uint16[file_len/2] &length=file_len;
} &byteorder=bigendian;

# RESPONSE FC=20
type ReadFileRecordResponse(header: ModbusTCP_TransportHeader) = record {
	byte_count: uint8; # &check(byte_count >= 0x07 && byte_count <= 0xF5);
	references: FileRecordResponse[] &length=byte_count;
} &let {
	deliver: bool = $context.flow.deliver_ReadFileRecordResponse(header, this);
} &byteorder=bigendian;

# Support data structure for the two following message types.
type ReferenceWithData = record {
	ref_type:       uint8;
	file_num:       uint16;
	record_num:     uint16;
	word_count:     uint16;
	register_value: uint16[word_count];
} &byteorder=bigendian;

# REQUEST FC=21
type WriteFileRecordRequest(header: ModbusTCP_TransportHeader) = record {
	byte_count: uint8;
	references: ReferenceWithData[] &length=byte_count;
} &let {
	deliver: bool = $context.flow.deliver_WriteFileRecordRequest(header, this);
} &byteorder=bigendian;

# RESPONSE FC=21
type WriteFileRecordResponse(header: ModbusTCP_TransportHeader) = record {
	byte_count: uint8;
	references: ReferenceWithData[] &length=byte_count;
} &let {
	deliver: bool = $context.flow.deliver_WriteFileRecordResponse(header, this);
} &byteorder=bigendian;

# REQUEST FC=22
type MaskWriteRegisterRequest(header: ModbusTCP_TransportHeader) = record {
	address:    uint16;
	and_mask:   uint16;
	or_mask:    uint16;
} &let {
	deliver: bool = $context.flow.deliver_MaskWriteRegisterRequest(header, this);
} &byteorder=bigendian;

# RESPONSE FC=22
type MaskWriteRegisterResponse(header: ModbusTCP_TransportHeader) = record {
	address:  uint16;
	and_mask: uint16;
	or_mask:  uint16;
} &let {
	deliver: bool = $context.flow.deliver_MaskWriteRegisterResponse(header, this);
} &byteorder=bigendian;

# REQUEST FC=23
type ReadWriteMultipleRegistersRequest(header: ModbusTCP_TransportHeader) = record {
	read_start_address:    uint16;
	read_quantity:         uint16; #                 &check(read_quantity <= 125);
	write_start_address:   uint16;
	write_quantity:        uint16; #                 &check(write_quantity <= 100);
	write_byte_count:      uint8;
	write_register_values: uint16[write_quantity] &length=write_byte_count;
} &let {
	 deliver: bool = $context.flow.deliver_ReadWriteMultipleRegistersRequest(header, this);
} &byteorder=bigendian;

# RESPONSE FC=23
type ReadWriteMultipleRegistersResponse(header: ModbusTCP_TransportHeader) = record {
	byte_count:  uint8;
	registers:   uint16[byte_count/2] &length=byte_count;
} &let {
	deliver: bool = $context.flow.deliver_ReadWriteMultipleRegistersResponse(header, this);
} &byteorder=bigendian;

# REQUEST FC=24
type ReadFIFOQueueRequest(header: ModbusTCP_TransportHeader) = record {
	start_address: uint16;
} &let{
	deliver: bool = $context.flow.deliver_ReadFIFOQueueRequest(header, this);
} &byteorder=bigendian;

# RESPONSE FC=24
type ReadFIFOQueueResponse(header: ModbusTCP_TransportHeader) = record {
	byte_count:    uint16; #             &check(byte_count <= 62);
	fifo_count:    uint16; #             &check(fifo_count <= 31);
	register_data: uint16[fifo_count] &length=fifo_count*2;
} &let {
	deliver: bool = $context.flow.deliver_ReadFIFOQueueResponse(header, this);
} &byteorder=bigendian;
