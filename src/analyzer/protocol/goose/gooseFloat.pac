# This record parses the GOOSE::Data of type FLOAT. Depending on the
# version of the GOOSE standard, it can be on 4 bytes, or more, in
# which case the first one indicates the number of bits the exponent
# is coded on. This implementation supports only the cases where the
# Data is encoded on 4 or 5 bytes and if the exponent is on 8 bits.
type ASN1FloatInternal(size: uint32) = record {
	getExpWidth: case size of {
		5 -> expWidth: uint8;
		default -> none: empty;
	};
	
	content: case formatSupported of {
		# parsed as an uint32 to take care of the endianness.
		true -> parsedValue: uint32;
		false -> bytes: bytestring &length = remainingBytes;
	} &requires(remainingBytes);
} &let {
	formatSupported: bool = size==4 || (size==5 && expWidth==8);
	
	remainingBytes: uint32 = size==5 ? 4 : size;
	
	value: double = interpret_bytes_of_int32_as_float(parsedValue); 
} &byteorder = bigendian;

function interpret_bytes_of_int32_as_float(intval: uint32): double
%{
	union {
		uint32 * asIntPtr;
		float * asFloatPtr;
	} ptr;
	
	ptr.asIntPtr = &intval;
	double rval = double(*(ptr.asFloatPtr));

	return rval;
%}

%code{
#include <climits>

//The code of this file can only work on devices where float is on 32 bits.
static_assert((sizeof(float) * CHAR_BIT) == 32, "Parsing of GOOSE::Data of type FLOAT can only be compiled on a system where \"float\" is on 4 bytes.");
%}
