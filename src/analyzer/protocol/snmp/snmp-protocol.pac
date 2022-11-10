# SNMPv1:  RFC 1157
# SNMPv2:  RFC 1901 and 3416
# SNMPv3:  RFC 3412
# Variable Bindings use definitions from RFC 1155 (and 3416).
#
# The SNMP protocol uses a well-defined subset of ASN.1 with the
# Basic Encoding Rules (BER).  Definite-length encodings are always
# used.  Primitive or non-constructor encodings are preferred over
# constructor encodings.

%include ../asn1/asn1.pac

type TopLevelMessage(is_orig: bool) = record {
	asn1_sequence_meta: ASN1SequenceMeta;
	version:            ASN1Integer;
	header:             Header(version_value, is_orig);
	pdu_or_not:         case have_plaintext_pdu(header) of {
		false -> none: empty;
		true  -> pdu:  PDU_Choice(header);
	};
} &let {
	version_value: int64 = binary_to_int64(version.encoding.content);
};

############################## SNMP Header Versions

enum SNMP_VersionTag {
	SNMPV1_TAG = 0,
	SNMPV2_TAG = 1,
	SNMPV3_TAG = 3,
};

type Header(version: int64, is_orig: bool) = case version of {
	SNMPV1_TAG -> v1:      v1Header(this);
	SNMPV2_TAG -> v2:      v2Header(this);
	SNMPV3_TAG -> v3:      v3Header(this);
	default    -> unknown: UnknownVersionHeader(this);
};

function have_plaintext_pdu(header: Header): bool =
	case header.version of {
		SNMPV1_TAG -> true;
		SNMPV2_TAG -> true;
		SNMPV3_TAG -> header.v3.next.tag == ASN1_SEQUENCE_TAG;
		default    -> false;
	};

type PDU_Choice(header: Header) = record {
	choice: ASN1EncodingMeta;
	pdu:    PDU(choice.tag, header);
};

type PDU(choice: uint8, header: Header) = case choice of {
	default -> unknown: UnknownPDU(choice, header);
};

refine casetype PDU += {
	# PDU choices from RFC 1157.
	0xa0    -> get_request:      GetRequestPDU(header);
	0xa1    -> get_next_request: GetNextRequestPDU(header);
	0xa2    -> response:         ResponsePDU(header);
	0xa3    -> set_request:      SetRequestPDU(header);
	0xa4    -> trap:             TrapPDU(header);
};

refine casetype PDU += {
	# PDU choices from RFC 3416.
	0xa5    -> get_bulk_request: GetBulkRequestPDU(header);
	0xa6    -> inform_request:   InformRequestPDU(header);
	0xa7    -> v2_trap:          v2TrapPDU(header);
	0xa8    -> report:           ReportPDU(header);
};

type v1Header(header: Header) = record {
	community:  ASN1OctetString;
};

type v2Header(header: Header) = record {
	community:  ASN1OctetString;
};

type v3Header(header: Header) = record {
	global_data:         v3HeaderData;
	security_parameters: ASN1OctetString;
	next:                ASN1EncodingMeta;
	scoped_pdu_data:     case next.tag of {
		ASN1_SEQUENCE_TAG     -> plaintext_pdu: v3ScopedPDU;
		ASN1_OCTET_STRING_TAG -> encrypted_pdu: EncryptedPDU(header);
		default               -> unknown_pdu:   UnknownScopedPDU(next.tag,
		                                                         header);
	};
};

type v3HeaderData = record {
	asn1_sequence_meta: ASN1SequenceMeta;
	id:                 ASN1Integer;
	max_size:           ASN1Integer;
	flags:              ASN1OctetString;
	security_model:     ASN1Integer;
};

type v3ScopedPDU = record {
	context_engine_id: ASN1OctetString;
	context_name:      ASN1OctetString;
};

type EncryptedPDU(header: Header) = record {
	data: bytestring &restofdata &transient;
};

type UnknownScopedPDU(tag: uint8, header: Header) = record {
	data: bytestring &restofdata &transient;
};

type UnknownVersionHeader(header: Header) = record {
	data: bytestring &restofdata &transient;
};

############################## SNMP PDUs

type CommonPDU(header: Header) = record {
	request_id:         ASN1Integer;
	error_status:       ASN1Integer;
	error_index:        ASN1Integer;
	var_bindings:       VarBindList;
};

type GetRequestPDU(header: Header) = record {
	pdu: CommonPDU(header);
};

type GetNextRequestPDU(header: Header) = record {
	pdu: CommonPDU(header);
};

type ResponsePDU(header: Header) = record {
	pdu: CommonPDU(header);
};

type SetRequestPDU(header: Header) = record {
	pdu: CommonPDU(header);
};

type TrapPDU(header: Header) = record {
	enterprise:         ASN1ObjectIdentifier;
	agent_addr:         NetworkAddress;
	generic_trap:       ASN1Integer;
	specific_trap:      ASN1Integer;
	time_stamp:         TimeTicks;
	var_bindings:       VarBindList;
};

type GetBulkRequestPDU(header: Header) = record {
	request_id:         ASN1Integer;
	non_repeaters:      ASN1Integer;
	max_repetitions:    ASN1Integer;
	var_bindings:       VarBindList;
};

type InformRequestPDU(header: Header) = record {
	pdu: CommonPDU(header);
};

type v2TrapPDU(header: Header) = record {
	pdu: CommonPDU(header);
};

type ReportPDU(header: Header) = record {
	pdu: CommonPDU(header);
};

type UnknownPDU(tag: uint8, header: Header) = record {
	data: bytestring &restofdata &transient;
};

type VarBindList = record {
	asn1_sequence_meta: ASN1SequenceMeta;
	bindings:           VarBind[];
};

type VarBind = record {
	asn1_sequence_meta: ASN1SequenceMeta;
	name:               ObjectName;
	value:              ObjectSyntax;
};

############################## Variable Binding Encodings (RFC 1155 and 3416)

type ObjectName = record {
	oid: ASN1ObjectIdentifier;
};

type ObjectSyntax = record {
	encoding: ASN1Encoding; # The tag may be a CHOICE among several;
};

type NetworkAddress = record {
	encoding: ASN1Encoding;
};

type TimeTicks = record {
	asn1_integer: ASN1Encoding;
};

enum AppSyntaxTypeTag {
	APP_IPADDRESS_TAG  = 0x40,
	APP_COUNTER32_TAG  = 0x41,
	APP_UNSIGNED32_TAG = 0x42,
	APP_TIMETICKS_TAG  = 0x43,
	APP_OPAQUE_TAG     = 0x44,
	APP_COUNTER64_TAG  = 0x46,
};

enum VarBindNullTag {
	VARBIND_UNSPECIFIED_TAG    = 0x05,
	VARBIND_NOSUCHOBJECT_TAG   = 0x80,
	VARBIND_NOSUCHINSTANCE_TAG = 0x81,
	VARBIND_ENDOFMIBVIEW_TAG   = 0x82,
};
