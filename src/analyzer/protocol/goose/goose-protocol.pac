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

#include "binpac_bytestring.h"
%}

%include ../asn1/asn1.pac
%include gooseInteger.pac
%include asn1BitString.pac

%header{
	StringVal* asn1_oid_internal_to_val(const ASN1ObjectIdentifierInternal* oidi);
%}

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
};

## This method returns the number of octets of a field in ASN.1 that
## does not carry the content of the field. Therefore, the result is
## 1 (the tag) + the number of octet used to indicate the length of
## the content.
function header_size_of_asn1_field(alen: ASN1Length): uint32
%{
	return ${alen.isMoreThanOneOctet} ? (2 + ${alen.sizeOfValue}) : 2;
%}

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
	datSet: RequiredValue(STRING);

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
	allData: GOOSEData[] &until($input.length == 0) &length=sequenceTotalLength.value;
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

type IEC_UTC_Time = record {
	secondsSince1970: uint32;
	fractionOfSecond: uint32;
} &byteorder = bigendian &let {
	nanoseconds: uint32 = utc_fraction_of_second_to_nanosecond(fractionOfSecond); 
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
};

type BoolAndUInt() = record {
	boolData: uint8;
	
	uintData: RequiredValue(U_INTEGER);
};

%include gooseData.pac

# ====================

