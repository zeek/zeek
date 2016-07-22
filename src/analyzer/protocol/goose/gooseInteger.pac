# Records that parse GOOSE Integer types, derived from ASN.1

%extern{
#include "binpac.h" // To get the endianness
#include "binpac_bytestring.h"
%}

function goose_int_bytes_to_int64(bytes: const_bytestring): int64
%{
	if(bytes.length()<1 || bytes.length()>8)
	//Boundaries: 
		return 0;
	
	int64 result;

	auto bytes_it = bytes.begin(); // iterator over the parsed bytes
	if(*bytes_it & 0x80) // if the first bit is 1
		result = -1; // the result is negative, we set all bits to 1
	else
		result = 0;  // else it's positive, we set them to 0

	/* The main loop
	 * Here we copy the parsed bytes one by one into the
	 * least significant byte of the result, which we left
	 * shift by 8 bits each time.
	 */
	const auto bytes_end = bytes.end();
	for(; bytes_it != bytes_end; ++bytes_it)
	{
		result <<= 8;
		result |= (int64)(*((unsigned char *)bytes_it));
				// We want the data to look like
				// 0x00000000000000?? so we want
				// to make sure the sign is not
				// kept when casting to int64.
	}
	
	return result;
%}


type GOOSESignedIntegerInternal(nbBytes: uint32) = record
{
	bytes: bytestring &length = nbBytes;
} &let {
	val: int64 = goose_int_bytes_to_int64(bytes);
};

function goose_uint_bytes_to_uint64(bytes: const_bytestring): uint64
%{
	if(bytes.length() < 1 || bytes.length() > 8)
	//Boundaries:
		return 0;
	
	uint64 result = 0;

	auto bytes_it = bytes.begin(); // iterator over the parsed bytes
	result = *bytes_it;

	/* The main loop
	 * Here we copy the parsed bytes one by one into the
	 * least significant byte of the result, which we left
	 * shift by 8 bits each time.
	 */
	const auto bytes_end = bytes.end();
	for(++bytes_it; bytes_it != bytes_end; ++bytes_it)
	{
		result <<= 8;
		result |= (uint64)(*bytes_it);
	}
	
	return result;
%}


type GOOSEUnsignedIntegerInternal(nbBytes: uint32) = record
{
	bytes: bytestring &length = nbBytes;
} &let {
	val: uint64 = goose_uint_bytes_to_uint64(bytes);
};
