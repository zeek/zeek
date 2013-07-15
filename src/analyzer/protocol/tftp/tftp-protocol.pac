
enum Opcodes {
	RRQ    = 1,
	WRQ    = 2,
	DATA   = 3,
	ACK    = 4,
	ERROR  = 5
};

type TFTP_Message = record {
	opcode:   uint16;
	op:       case opcode of {
		RRQ     -> read_request    : ReadRequest;
		WRQ     -> write_request   : WriteRequest;
		DATA    -> data            : DataChunk;
		ACK     -> acknowledgment  : Acknowledgment;
		ERROR   -> error           : Error;
		default -> failure         : FAILURE(opcode);
	};
	junk: bytestring &restofdata;
} &byteorder=bigendian;

type TFTP_STRING = record {
	str:  RE/[^\x00]+/;
	null: uint8;
};

type ReadRequest = record {
	file: TFTP_STRING;
	type: TFTP_STRING;
};

type WriteRequest = record {
	file: TFTP_STRING;
	type: TFTP_STRING;
};

type DataChunk = record {
	block: uint16;
	data:  bytestring &restofdata;
};

type Acknowledgment = record {
	block: uint16;
};

type Error = record {
	errcode: uint16;
	errmsg:  TFTP_STRING;
};

type FAILURE(opcode: uint16) = record {
	blank: empty;
};
