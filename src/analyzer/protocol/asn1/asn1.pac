############################## ASN.1 Encodings

enum ASN1TypeTag {
	ASN1_INTEGER_TAG           = 0x02,
	ASN1_OCTET_STRING_TAG      = 0x04,
	ASN1_NULL_TAG              = 0x05,
	ASN1_OBJECT_IDENTIFIER_TAG = 0x06,
	ASN1_SEQUENCE_TAG          = 0x30,
};

type ASN1Encoding = record {
	meta:    ASN1EncodingMeta;
	content: bytestring &length = meta.length;
};

type ASN1EncodingMeta = record {
	tag:      uint8;
	len:      uint8;
	more_len: bytestring &length = long_len ? len & 0x7f : 0;
} &let {
	long_len: bool = len & 0x80;
	length:   uint64 = long_len ? binary_to_int64(more_len) : len & 0x7f;
};

type ASN1SequenceMeta = record {
	encoding: ASN1EncodingMeta;
};

type ASN1Integer = record {
	encoding: ASN1Encoding;
};

type ASN1OctetString = record {
	encoding: ASN1Encoding;
};

type ASN1ObjectIdentifier = record {
	encoding: ASN1Encoding;
};

type ASN1Boolean = record {
	encoding: ASN1Encoding;
};

type ASN1Enumerated = record {
	encoding: ASN1Encoding;
};

############################## ASN.1 Conversion Functions

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
