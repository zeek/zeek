# Record of the bit-string as specified in ASN.1

type ASN1BitString(nbBytes: uint32) = record
{
	paddingBits: uint8;
	data: bytestring &length = nbBytes-1;
};

# Utility C++ method used by the next BinPAC function
%header{
template<typename ByteIterator>
void getBoolsFromByte(ByteIterator & byte_it, ByteIterator & byte_end, VectorVal & vv, uint8 & current_byte, unsigned int & vector_it)
{
	for(; byte_it != byte_end; ++byte_it)
	{
		current_byte = *byte_it;
		vv.Assign(vector_it, new Val(0x80 & current_byte, TYPE_BOOL));
		++vector_it;
		vv.Assign(vector_it, new Val(0x40 & current_byte, TYPE_BOOL));
		++vector_it;
		vv.Assign(vector_it, new Val(0x20 & current_byte, TYPE_BOOL));
		++vector_it;
		vv.Assign(vector_it, new Val(0x10 & current_byte, TYPE_BOOL));
		++vector_it;
		vv.Assign(vector_it, new Val(0x8 & current_byte, TYPE_BOOL));
		++vector_it;
		vv.Assign(vector_it, new Val(0x4 & current_byte, TYPE_BOOL));
		++vector_it;
		vv.Assign(vector_it, new Val(0x2 & current_byte, TYPE_BOOL));
		++vector_it;
		vv.Assign(vector_it, new Val(0x1 & current_byte, TYPE_BOOL));
		++vector_it;
		}
}
%}

function asn1_bitstring_to_val(bitStringRecord: ASN1BitString): VectorVal
%{
	// Get the main information from the record :
	const auto & data = ${bitStringRecord.data};
	uint8 pad = ${bitStringRecord.paddingBits};

	// Initializing return value :
	auto vv = new VectorVal(new VectorType(base_type(TYPE_BOOL)));
	
	auto byte_it = data.begin(), bytes_end = data.end();
	if(byte_it == bytes_end) // If no bytes
		return vv; // Return empty vector

	vv->Resize(8*data.length() - pad);

	unsigned int vi=0; // Vector index
	uint8 current_byte;

	if(pad) {
		--bytes_end;

		//Copy the content of the bytes full of data
		getBoolsFromByte(byte_it, bytes_end, *vv, current_byte, vi);

		//Last byte
		current_byte = *byte_it;
		uint8 mask = 0x80;
		for(auto lbi=0, max=8-pad ; lbi<max; ++lbi) // "lbi" stands for "last byte index"
		{
			vv->Assign(vi, new Val(mask & current_byte, TYPE_BOOL));
			++vi;
			mask >>= 1;
		}
	}
	else {
		//Copy the content of all the bytes
		getBoolsFromByte(byte_it, bytes_end, *vv, current_byte, vi);
	}

	return vv;
%}
