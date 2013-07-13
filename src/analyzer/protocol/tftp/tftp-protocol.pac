
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
		default -> failure         : Failure;
	};
	crap: bytestring &restofdata;
} &byteorder=bigendian;

type ReadRequest = record {
	file: RE/[^\x00]+/;
	null: uint8;
	type: RE/[^\x00]+/;
};

type WriteRequest = record {
	file: RE/[^\x00]+/;
	null: uint8;
	type: RE/[^\x00]+/;
};

type DataChunk = record {
	block: uint16;
	data:  bytestring &restofdata;
};

type Acknowledgment = record {
	block: uint16;
};

type Error = record {
	
};

type Failure = record {
	nothing: empty;
};