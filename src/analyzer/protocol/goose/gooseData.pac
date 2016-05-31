
## ======= GOOSEData ===

type GOOSEData = record {
	tag: uint8;
	len: ASN1Length;

	content: GOOSEDataContent(tag, len.value);
} &let {
	totalSize: uint32 = (len.isMoreThanOneOctet ? 2+len.sizeOfValue : 2) + len.value;
	debug: bool = displayByte(tag);
};

type GOOSEDataContent(tag: uint8, size: uint32) = record {
	data: case tag of {
		# To parse the arrays, only the length is necessary
		ARRAY -> none : empty;
		STRUCTURE -> none2 : empty;

		BOOLEAN -> boolean: uint8;
		BIT_STRING -> bitString: ASN1BitString(size);
		SIGNED_INTEGER -> intVal: GOOSESignedIntegerInternal(size);
		UNSIGNED_INTEGER -> uintVal: GOOSEUnsignedIntegerInternal(size);  
		FLOATING_POINT -> floatVal: bytestring &length = size; #ASN1FloatInternal(size); # TODO: read non-free IEC61850
		REAL -> realVal: ASN1RealInternal;
		OCTET_STRING -> bs: bytestring &length = size;
		VISIBLE_STRING -> string: bytestring &length = size; 
		BINARY_TIME -> timeOfDay: bytestring &length = size;
		BCD -> bcd: GOOSESignedIntegerInternal(size);
		BOOLEAN_ARRAY -> boolArray: ASN1BitString(size);
		OBJ_ID -> objId: ASN1ObjectIdentifierInternal(size);
		UTCTIME -> utcTime: IEC_UTC_Time;
		MMS_STRING -> mmsString: bytestring &length = size;
	};
};

enum GOOSEDataTypes {
	ARRAY = 0x81,
	STRUCTURE = 0x82,
	BOOLEAN = 0x83,
	BIT_STRING = 0x84,
	SIGNED_INTEGER = 0x85,
	UNSIGNED_INTEGER = 0x86,
	FLOATING_POINT = 0x87,
	REAL = 0x88,
	OCTET_STRING = 0x89,
	VISIBLE_STRING = 0x8a,
	# no 0x8b
	BINARY_TIME = 0x8c,
	BCD = 0x8d,
	BOOLEAN_ARRAY = 0x8e,
	OBJ_ID = 0x8f,
	MMS_STRING = 0x90,
	UTCTIME = 0x91 
};


## The following record and associated functions are a workaround for the
## circular record dependency issue
type GOOSEDataArrayHead(size: uint32) = record {
	# Parses nothing, which means that all GOOSE::Data will be parsed
	# as one big array. The C++ code will have to rebuild the tree.
} &let {
	contentSize: uint32 = size;
};


#function goose_data_as_val(gdata: GOOSEData): RecordVal
#{
#	
#}

## ====================
