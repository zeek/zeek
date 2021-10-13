%extern{
#include <cstdlib>
%}

%header{
	zeek::ValPtr asn1_integer_to_val(const ASN1Encoding* i, zeek::TypeTag t);
	zeek::ValPtr asn1_integer_to_val(const ASN1Integer* i, zeek::TypeTag t);
	zeek::StringValPtr asn1_oid_to_val(const ASN1Encoding* oid);
	zeek::StringValPtr asn1_oid_to_val(const ASN1ObjectIdentifier* oid);
	zeek::StringValPtr asn1_octet_string_to_val(const ASN1Encoding* s);
	zeek::StringValPtr asn1_octet_string_to_val(const ASN1OctetString* s);
%}

############################## ASN.1 Encodings

enum ASN1TypeTag {
	ASN1_INTEGER_TAG           = 0x02,
	ASN1_OCTET_STRING_TAG      = 0x04,
	ASN1_NULL_TAG              = 0x05,
	ASN1_OBJECT_IDENTIFIER_TAG = 0x06,
	ASN1_SEQUENCE_TAG          = 0x30,
	ASN1_APP_TAG_OFFSET	       = 0x60,
	ASN1_INDEX_TAG_OFFSET	   = 0xa0,
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
	long_len        : bool = (len & 0x80) > 0;
	length:   uint64 = long_len ? binary_to_int64(more_len) : len;
	index           : uint8 = tag - ASN1_INDEX_TAG_OFFSET;
};

type ASN1OptionalEncodingMeta(is_present: bool, previous_metadata: ASN1EncodingMeta) = case is_present of {
	true  -> data: ASN1EncodingMeta;
	false -> none: empty;
} &let {
	length: uint64 = is_present ? data.length : previous_metadata.length;
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

type SequenceElement(grab_content: bool) = record {
	index_meta:    ASN1EncodingMeta;
	have_content:  case grab_content of {
		true  -> data: ASN1Encoding;
		false -> meta: ASN1EncodingMeta;
	};
} &let {
	index:  uint8 = index_meta.index;
	length: uint64 = index_meta.length;
};

type Array = record {
	array_meta: ASN1EncodingMeta;
	data:       ASN1Encoding[];
};

############################## ASN.1 Conversion Functions

# Converts an 8-byte string into an int64. If this string is longer than
# 8 bytes, it reports a weird and returns zero.
function binary_to_int64(bs: bytestring): int64
	%{
	int64 rval = 0;

	if ( bs.length() > 8 )
		{
		zeek::reporter->Weird("asn_binary_to_int64_shift_too_large", zeek::util::fmt("%d", bs.length()));
		return 0;
		}

	for ( int i = 0; i < bs.length(); ++i )
		{
		uint64 byte = bs[i];
		rval |= byte << (8 * (bs.length() - (i + 1)));
		}

	return rval;
	%}

%code{

zeek::ValPtr asn1_integer_to_val(const ASN1Integer* i, zeek::TypeTag t)
	{
	return asn1_integer_to_val(i->encoding(), t);
	}

zeek::ValPtr asn1_integer_to_val(const ASN1Encoding* i, zeek::TypeTag t)
	{
	auto v = binary_to_int64(i->content());

	switch ( t ) {
	case zeek::TYPE_BOOL:
		return zeek::val_mgr->Bool(v);
	case zeek::TYPE_INT:
		return zeek::val_mgr->Int(v);
	case zeek::TYPE_COUNT:
		return zeek::val_mgr->Count(v);
	default:
		zeek::reporter->Error("bad asn1_integer_to_val tag: %s", zeek::type_name(t));
		return zeek::val_mgr->Count(v);
	}
	}

zeek::StringValPtr asn1_oid_to_val(const ASN1ObjectIdentifier* oid)
	{
	return asn1_oid_to_val(oid->encoding());
	}

zeek::StringValPtr asn1_oid_to_val(const ASN1Encoding* oid)
	{
	vector<uint64> oid_components;
	vector<vector<uint8> > subidentifiers;
	vector<uint64> subidentifier_values;
	vector<uint8> subidentifier;
	bytestring const& bs = oid->content();

	for ( int i = 0; i < bs.length(); ++i )
		{
		if ( bs[i] & 0x80 )
			subidentifier.push_back(bs[i] & 0x7f);
		else
			{
			subidentifier.push_back(bs[i]);
			subidentifiers.push_back(subidentifier);
			subidentifier.clear();
			}
		}

	if ( ! subidentifier.empty() || subidentifiers.size() < 1 )
		// Underflow.
		return zeek::val_mgr->EmptyString();

	for ( auto subidentifier : subidentifiers )
		{
		uint64 value = 0;

		for ( size_t j = 0; j < subidentifier.size(); ++j )
			{
			uint64 byte = subidentifier[j];
			value |= byte << (7 * (subidentifier.size() - (j + 1)));
			}

		subidentifier_values.push_back(value);
		}

	string rval;

	for ( size_t i = 0; i < subidentifier_values.size(); ++i )
		{
		char tmp[32];

		if ( i > 0 )
			{
			snprintf(tmp, sizeof(tmp), ".%" PRIu64, subidentifier_values[i]);
			rval += tmp;
			}
		else
			{
			std::div_t result = std::div(subidentifier_values[i], 40);
			snprintf(tmp, sizeof(tmp), "%d.%d", result.quot, result.rem);
			rval += tmp;
			}
		}

	return zeek::make_intrusive<zeek::StringVal>(rval);
	}

zeek::StringValPtr asn1_octet_string_to_val(const ASN1OctetString* s)
	{
	return asn1_octet_string_to_val(s->encoding());
	}

zeek::StringValPtr asn1_octet_string_to_val(const ASN1Encoding* s)
	{
	bytestring const& bs = s->content();
	return zeek::make_intrusive<zeek::StringVal>(bs.length(), reinterpret_cast<const char*>(bs.data()));
	}
%}
