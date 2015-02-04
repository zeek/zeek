%header{
Val* GetTimeFromAsn1(const KRB_Time* atime, int64 usecs);
Val* GetTimeFromAsn1(StringVal* atime, int64 usecs);

Val* asn1_integer_to_val(const ASN1Encoding* i, TypeTag t);
Val* asn1_integer_to_val(const ASN1Integer* i, TypeTag t);
%}

%code{
Val* GetTimeFromAsn1(const KRB_Time* atime, int64 usecs)
	{
	return GetTimeFromAsn1(bytestring_to_val(atime->time()), usecs);
	}

Val* GetTimeFromAsn1(StringVal* atime, int64 usecs)
	{
	time_t lResult = 0;

	char lBuffer[17];
	char* pBuffer = lBuffer;

	size_t lTimeLength = atime->Len();
	char * pString = (char *) atime->Bytes();
	
	if ( lTimeLength != 15 && lTimeLength != 17 )
		return 0;

	if (lTimeLength == 17 )
		pString = pString + 2;
		
	memcpy(pBuffer, pString, 15);
	*(pBuffer+15) = '\0';

	tm lTime;
	lTime.tm_sec  = ((lBuffer[12] - '0') * 10) + (lBuffer[13] - '0');
	lTime.tm_min  = ((lBuffer[10] - '0') * 10) + (lBuffer[11] - '0');
	lTime.tm_hour = ((lBuffer[8] - '0') * 10) + (lBuffer[9] - '0');
	lTime.tm_mday = ((lBuffer[6] - '0') * 10) + (lBuffer[7] - '0');
	lTime.tm_mon  = (((lBuffer[4] - '0') * 10) + (lBuffer[5] - '0')) - 1;
	lTime.tm_year = ((lBuffer[0] - '0') * 1000) + ((lBuffer[1] - '0') * 100) + ((lBuffer[2] - '0') * 10) + (lBuffer[3] - '0') - 1900;

	lTime.tm_wday = 0;
	lTime.tm_yday = 0;
	lTime.tm_isdst = 0;

	lResult = timegm(&lTime);

	if ( !lResult )
		lResult = 0;

	return new Val(double(lResult + (usecs/100000)), TYPE_TIME);
	}

	Val* asn1_integer_to_val(const ASN1Integer* i, TypeTag t)
	{
	return asn1_integer_to_val(i->encoding(), t);
	}

	Val* asn1_integer_to_val(const ASN1Encoding* i, TypeTag t)
	{
	return new Val(binary_to_int64(i->content()), t);
	}
%}

type ASN1Encoding = record {
     meta:    ASN1EncodingMeta;
     content: bytestring &length = meta.length;
};

type ASN1EncodingMeta = record {
	tag:      	uint8;
	len:      	uint8;
	more_len: 	bytestring &length = long_len ? (len & 0x7f) : 0;
} &let {
	long_len: 	bool = (len & 0x80) > 0;
	length:   	uint64 = long_len ? binary_to_int64(more_len) : len;
	has_index:	bool = (tag >= ASN1_INDEX_TAG_OFFSET);
	index:    	uint8 = tag - ASN1_INDEX_TAG_OFFSET;
};

type ASN1OptionalEncodingMeta(is_present: bool, previous_metadata: ASN1EncodingMeta) = case is_present of {
	true  -> data: ASN1EncodingMeta;
	false -> none: empty;
} &let {
	length: uint64 = is_present ? data.length : previous_metadata.length;
};

type ASN1Integer = record {
     encoding: ASN1Encoding;
};

type ASN1OctetString = record {
     encoding: ASN1Encoding;
};

type SequenceElement(grab_content: bool) = record {
     index_meta: ASN1EncodingMeta;
     have_content: case grab_content of {
     	true  -> data: ASN1Encoding;
		false -> meta: ASN1EncodingMeta;
     };
} &let {
     index: uint8 = index_meta.index;
     length: uint64 = index_meta.length;
};

type Array = record {
     array_meta: ASN1EncodingMeta;
     data: ASN1Encoding[];
};

function binary_to_int64(bs: bytestring): int64
	%{
	int64 rval = 0;

	for ( int i = 0; i < bs.length(); ++i )
	    {
	    uint64 byte = bs[i];
	    rval |= byte << (8 * (bs.length() - (i + 1)));
	    }

	return rval;
	%}

