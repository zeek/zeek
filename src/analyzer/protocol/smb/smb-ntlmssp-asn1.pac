# Supporting types for ASN.1
#
# From the Kerberos analyzer
#
# TODO: Figure out a way to include this code only once.

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
	 index:    uint8 = tag - 160;
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