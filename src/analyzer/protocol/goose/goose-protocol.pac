## GOOSE Message Type
## GOOSE is based on ASN.1 and this file has been written according to
## the IEC61850 8.1 ; An asn file describing most of it can be found
## in the source code of Wireshark.
##
## This PAC file includes functions that export the BinPAC objects to
## BroVal objects.

# === ASN.1 parsing tools ===

%extern{
#include <string.h>
#include <math.h>
#include <iostream>

#include "binpac_bytestring.h"
%}

%include ../asn1/asn1.pac
%include gooseInteger.pac
%include asn1BitString.pac

%header{
	StringVal* asn1_oid_internal_to_val(const ASN1ObjectIdentifierInternal* oidi);
%}

#     === Debugging tools ===

function debugASNLength(id: uint8, sizeOfVal: uint8, val: uint32): bool
%{
	std::cout << "Identifier : " << (int)id 
		  << "; sizeOfValue: " << (int)sizeOfVal 
		  << "; Resulting length : " << val 
		  << std::endl;
	return true;
%}

function displayByte(byte: uint8): bool
%{
	std::cout << std::hex << +byte << std::dec << std::endl;
	return true;
%}

#     =======================

# The input bytystring has to be of size 1 or more.
function bytestring_to_uint32(s: const_bytestring): uint32
	%{
	//Get iterators over the bytestring
	auto s_iter = s.begin();
	const auto s_end = s.end();

	uint32 returnValue = *s_iter; //Copy first byte
	
	//Copy the rest of the bytes, keeping in mind that all values are positive
	for(++s_iter; s_iter != s_end ; ++s_iter) {
		returnValue <<= 8;
		returnValue |= *s_iter;
	}

	return returnValue; 
	%}

## Redefined to be unsigned.
type ASN1Length = record {
	Identifier: uint8; # Identifies whether or not the length is encoded on folowing bytes.
	
	FollowingBytes: case isMoreThanOneOctet of {
		true  -> ValueBytes: bytestring
				&requires(sizeOfValue)
				&length = sizeOfValue
				&check(sizeOfValue > 0); # Does not make sense otherwise
		false -> none: empty;
	} &requires(isMoreThanOneOctet)
	  &requires(sizeOfValue);
		
} &let {
	isMoreThanOneOctet: bool = (Identifier & 0x80);
	
	sizeOfValue: uint8 = (Identifier & 0x7f)
		&if(isMoreThanOneOctet)
		&check(sizeOfValue < 5); # No packet is more than 2^32 bytes long.

	value: uint32 = (isMoreThanOneOctet ?
				bytestring_to_uint32(ValueBytes) :
				Identifier
				    # implicit cast from uint8 to uint32
			);

	recordSize: uint8 = (isMoreThanOneOctet ? 1+sizeOfValue : 1);

	debug: bool = debugASNLength(Identifier, (isMoreThanOneOctet?sizeOfValue:1), value);
};

function asn1_real_to_double(m: int64, b: int64, e: int64): double
%{
	if(b == 2)
	{
		//Result may be invalid if e is too high.
		if(e < 0)
			return ((double)m) / (1<<e);
		else
			return (double)(m << e);
	}
	else
		return m * pow(10.0, (double)e);
%}

type ASN1RealInternal = record {
	mantissa: RequiredValue(INTEGER);
	base: RequiredValue(INTEGER) &check(base.gooseInt.val==2 || base.gooseInt.val==10);
	exponent: RequiredValue(INTEGER);
} &let {
	value: double = asn1_real_to_double(mantissa.gooseInt.val, base.gooseInt.val, exponent.gooseInt.val);
};

type ASN1ObjectIdentifierInternal(size: uint32) = record
{
	data: bytestring &length = size;
};

%code{
	StringVal* asn1_oid_internal_to_val(const ASN1ObjectIdentifierInternal* oidi)
		{
		return asn1_oid_to_val(oidi->data());
		}
%}

# ===========================
# ===========================

## The main record :
type GOOSE_Message = record {
	APPDI : uint16;
	Length : uint16;

	Reserved1 : uint16;
	Reserved2 : uint16;

	PDU_Type : uint8;
	PDU : case PDU_Type of {
		GOOSE_PDU -> goosePdu: IECGoosePdu;
		default   -> gseMngtPdu: GSEMngtPdu;
	};
} &byteorder = bigendian;

enum PDU_Type {
	GOOSE_PDU = 0x61,
	#GOOSE_MNGT_PDU = ??? ## Tag unknown by the author of this file.
};


type GSEMngtPdu = record {
	rest : bytestring &restofdata;
} &byteorder = bigendian;


type IECGoosePdu = record {
	size : ASN1Length;	
	
	gocbRef: RequiredValue(STRING);
	timeAllowedToLive: RequiredValue(U_INTEGER);
	dataSet: RequiredValue(STRING);

	# The next field is optionnal.
	nextTag: uint8;
	nextLength: ASN1Length;	
	goIDIsPresent: case nextTag of {
		0x83 -> goIDAndT: GOIDThenT(nextLength.value);
		0x84 -> t: IEC_UTC_Time;
	};
	
	stNum: RequiredValue(U_INTEGER);
	sqNum: RequiredValue(U_INTEGER);

	testAndConfRev: BoolDefaultFalseThenUInt(0x87);
	ndsComAndNumDatSetEntries: BoolDefaultFalseThenUInt(0x89);

	sequenceTag: uint8;
	sequenceTotalLength: ASN1Length;
	allData: GOOSEData[] &until($input.length == 0);
} &let {
	has_goID: bool = nextTag == 0x83;
};

type GOIDThenT(goIDLength: uint32) = record {
	goID: bytestring &length = goIDLength;

	t: RequiredValue(UTC_TIME);
};

## UTC time as described in RFC 1305. The first 4 bytes parsed
## are in the correct order to form an uint32 and the resulting
## number is the number of seconds between the measured instant
## and 0h of the 1rst of January 1970. The last 4 bytes are in
## the correct order to form the uint32 number of 2^(-32)second
## since the last round second.

function utc_fraction_of_second_to_nanosecond(fraction: uint32): uint32
%{
	return (((uint64)fraction) * 1000000000) >> 32;
	//fraction * (1000 * 1000 * 1000) / 2^32
%}

function debugUTCTime(seconds: uint32, nanoseconds: uint32): bool
%{
	uint32 speryear = 3600 * 6 * (365 * 4 +1);
	uint32 years = seconds / speryear;
	
	std::cout << "year : " << 1970 + years << "; nanoseconds : " << nanoseconds << std::endl; 

	return true;
%}

type IEC_UTC_Time = record {
	secondsSince1970: uint32;
	fractionOfSecond: uint32;
} &byteorder = bigendian &let {
	nanoseconds: uint32 = utc_fraction_of_second_to_nanosecond(fractionOfSecond); 
	debug: bool = debugUTCTime(secondsSince1970, nanoseconds);
};

# Converting IEC_UTC_Time to BroVal
function gooseT_as_val(utc: IEC_UTC_Time): RecordVal
%{
	RecordVal * rv = new RecordVal(BifType::Record::GOOSE::UTCTime);

	rv->Assign(0, new Val(${utc.secondsSince1970}, TYPE_COUNT));
	rv->Assign(1, new Val(${utc.nanoseconds}, TYPE_COUNT));

	return rv;
%}

# === Helper types for goosePdu ===

enum GOOSEType {
	STRING,
	INTEGER,
	U_INTEGER,
	UTC_TIME
};

type RequiredValue(type:GOOSEType)
	= record
{
	tag: uint8;
	
	length: ASN1Length;
	data: case type of {
		STRING   -> str: bytestring &length = length.value;
		INTEGER  -> gooseInt: GOOSESignedIntegerInternal(length.value);
		U_INTEGER-> gooseUInt: GOOSEUnsignedIntegerInternal(length.value);
		UTC_TIME -> val: IEC_UTC_Time;
	};
};

function debugBool(val: bool): bool
%{
	std::cout << "Boolean value : " << val << std::endl;
	return true;
%}

type BoolDefaultFalseThenUInt(expectedBoolTag: uint8) = record
{
	firstTag: uint8;
	firstLength: ASN1Length;
	
	nextBytes: case boolValIsPresent of {
		true -> both: BoolAndUInt;
		false -> uintData: GOOSEUnsignedIntegerInternal(firstLength.value);
	} &requires(boolValIsPresent);

} &let {
	boolValIsPresent: bool = (firstTag == expectedBoolTag);

	boolVal: bool = (boolValIsPresent && both.boolData); 
	uintVal: uint64 = (boolValIsPresent
				? both.uintData.gooseUInt.val
				: uintData.val);
	debug: bool = debugBool(boolVal);
};

type BoolAndUInt() = record {
	boolData: uint8;
	
	uintData: RequiredValue(U_INTEGER);
};

## ======= GOOSEData ===
type GOOSEData = record {
	tag: uint8;
	len: ASN1Length;

	content: GOOSEDataContent(tag, len.value);
} &let {
	totalSize: uint32 = 1 + len.recordSize + len.value;
	debug: bool = displayByte(tag);
};

type GOOSEDataContent(tag: uint8, size: uint32) = record {
	data: case tag of {
		ARRAY -> array: GOOSEDataArrayHead(size);
		STRUCTURE -> structure: GOOSEDataArrayHead(size);
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
} &byteorder = bigendian;

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

## ====================
# ====================

