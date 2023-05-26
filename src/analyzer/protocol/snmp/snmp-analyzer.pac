%extern{
#include <cstdlib>
#include <vector>
#include <string>

#include "zeek/net_util.h"
#include "zeek/util.h"
%}

%header{
zeek::AddrValPtr network_address_to_val(const ASN1Encoding* na);
zeek::AddrValPtr network_address_to_val(const NetworkAddress* na);
zeek::ValPtr     asn1_obj_to_val(const ASN1Encoding* obj);

zeek::RecordValPtr build_hdr(const Header* header);
zeek::RecordValPtr build_hdrV3(const Header* header);
zeek::VectorValPtr build_bindings(const VarBindList* vbl);
zeek::RecordValPtr build_pdu(const CommonPDU* pdu);
zeek::RecordValPtr build_trap_pdu(const TrapPDU* pdu);
zeek::RecordValPtr build_bulk_pdu(const GetBulkRequestPDU* pdu);
%}

%code{

zeek::AddrValPtr network_address_to_val(const NetworkAddress* na)
	{
	return network_address_to_val(na->encoding());
	}

zeek::AddrValPtr network_address_to_val(const ASN1Encoding* na)
	{
	bytestring const& bs = na->content();

	// IPv6 can probably be presumed to be a octet string of length 16,
	// but standards don't seem to currently make any provisions for IPv6,
	// so ignore anything that can't be IPv4.
	if ( bs.length() != 4 )
		return zeek::make_intrusive<zeek::AddrVal>(zeek::IPAddr());

	const u_char* data = reinterpret_cast<const u_char*>(bs.data());
	uint32 network_order = zeek::extract_uint32(data);
	return zeek::make_intrusive<zeek::AddrVal>(ntohl(network_order));
	}

zeek::ValPtr asn1_obj_to_val(const ASN1Encoding* obj)
	{
	zeek::RecordValPtr rval = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SNMP::ObjectValue);
	uint8 tag = obj->meta()->tag();

	rval->Assign(0, tag);

	switch ( tag ) {
	case VARBIND_UNSPECIFIED_TAG:
	case VARBIND_NOSUCHOBJECT_TAG:
	case VARBIND_NOSUCHINSTANCE_TAG:
	case VARBIND_ENDOFMIBVIEW_TAG:
		break;

	case ASN1_OBJECT_IDENTIFIER_TAG:
		rval->Assign(1, asn1_oid_to_val(obj));
		break;

	case ASN1_INTEGER_TAG:
		rval->Assign(2, asn1_integer_to_val(obj, zeek::TYPE_INT));
		break;

	case APP_COUNTER32_TAG:
	case APP_UNSIGNED32_TAG:
	case APP_TIMETICKS_TAG:
	case APP_COUNTER64_TAG:
		rval->Assign(3, asn1_integer_to_val(obj, zeek::TYPE_COUNT));
		break;

	case APP_IPADDRESS_TAG:
		rval->Assign(4, network_address_to_val(obj));
		break;

	case ASN1_OCTET_STRING_TAG:
	case APP_OPAQUE_TAG:
	default:
		rval->Assign(5, asn1_octet_string_to_val(obj));
		break;
	}

	return rval;
	}

zeek::ValPtr time_ticks_to_val(const TimeTicks* tt)
	{
	return asn1_integer_to_val(tt->asn1_integer(), zeek::TYPE_COUNT);
	}

zeek::RecordValPtr build_hdr(const Header* header)
	{
	auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SNMP::Header);
	rv->Assign(0, static_cast<uint64_t>(header->version()));

	switch ( header->version() ) {
	case SNMPV1_TAG:
		{
		auto v1 = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SNMP::HeaderV1);
		v1->Assign(0, asn1_octet_string_to_val(header->v1()->community()));
		rv->Assign(1, std::move(v1));
		}
		break;

	case SNMPV2_TAG:
		{
		auto v2 = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SNMP::HeaderV2);
		v2->Assign(0, asn1_octet_string_to_val(header->v2()->community()));
		rv->Assign(2, std::move(v2));
		}
		break;

	case SNMPV3_TAG:
		{
		rv->Assign(3, build_hdrV3(header));
		}
		break;
	}

	return rv;
	}

zeek::RecordValPtr build_hdrV3(const Header* header)
	{
	auto v3 = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SNMP::HeaderV3);
	const v3Header* v3hdr = header->v3();
	const v3HeaderData* global_data = v3hdr->global_data();
	bytestring const& flags = global_data->flags()->encoding()->content();
	uint8 flags_byte = flags.length() > 0 ? flags[0] : 0;

	v3->Assign(0, asn1_integer_to_val(global_data->id(), zeek::TYPE_COUNT));
	v3->Assign(1, asn1_integer_to_val(global_data->max_size(), zeek::TYPE_COUNT));
	v3->Assign(2, flags_byte);
	v3->Assign(3, static_cast<bool>(flags_byte & 0x01));
	v3->Assign(4, static_cast<bool>(flags_byte & 0x02));
	v3->Assign(5, static_cast<bool>(flags_byte & 0x04));
	v3->Assign(6, asn1_integer_to_val(global_data->security_model(), zeek::TYPE_COUNT));
	v3->Assign(7, asn1_octet_string_to_val(v3hdr->security_parameters()));

	if ( v3hdr->next()->tag() == ASN1_SEQUENCE_TAG )
		{
		const v3ScopedPDU* spdu = v3hdr->plaintext_pdu();
		auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SNMP::ScopedPDU_Context);
		rv->Assign(0, asn1_octet_string_to_val(spdu->context_engine_id()));
		rv->Assign(1, asn1_octet_string_to_val(spdu->context_name()));
		v3->Assign(8, std::move(rv));
		}

	return v3;
	}

zeek::VectorValPtr build_bindings(const VarBindList* vbl)
	{
	auto vv = zeek::make_intrusive<zeek::VectorVal>(zeek::BifType::Vector::SNMP::Bindings);

	for ( size_t i = 0; i < vbl->bindings()->size(); ++i )
		{
		VarBind* vb = (*vbl->bindings())[i];
		auto binding = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SNMP::Binding);
		binding->Assign(0, asn1_oid_to_val(vb->name()->oid()));
		binding->Assign(1, asn1_obj_to_val(vb->value()->encoding()));
		vv->Assign(i, std::move(binding));
		}

	return vv;
	}

zeek::RecordValPtr build_pdu(const CommonPDU* pdu)
	{
	auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SNMP::PDU);
	rv->Assign(0, asn1_integer_to_val(pdu->request_id(), zeek::TYPE_INT));
	rv->Assign(1, asn1_integer_to_val(pdu->error_status(), zeek::TYPE_INT));
	rv->Assign(2, asn1_integer_to_val(pdu->error_index(), zeek::TYPE_INT));
	rv->Assign(3, build_bindings(pdu->var_bindings()));
	return rv;
	}

zeek::RecordValPtr build_trap_pdu(const TrapPDU* pdu)
	{
	auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SNMP::TrapPDU);
	rv->Assign(0, asn1_oid_to_val(pdu->enterprise()));
	rv->Assign(1, network_address_to_val(pdu->agent_addr()));
	rv->Assign(2, asn1_integer_to_val(pdu->generic_trap(), zeek::TYPE_INT));
	rv->Assign(3, asn1_integer_to_val(pdu->specific_trap(), zeek::TYPE_INT));
	rv->Assign(4, time_ticks_to_val(pdu->time_stamp()));
	rv->Assign(5, build_bindings(pdu->var_bindings()));
	return rv;
	}

zeek::RecordValPtr build_bulk_pdu(const GetBulkRequestPDU* pdu)
	{
	auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SNMP::BulkPDU);
	rv->Assign(0, asn1_integer_to_val(pdu->request_id(), zeek::TYPE_INT));
	rv->Assign(1, asn1_integer_to_val(pdu->non_repeaters(), zeek::TYPE_COUNT));
	rv->Assign(2, asn1_integer_to_val(pdu->max_repetitions(), zeek::TYPE_COUNT));
	rv->Assign(3, build_bindings(pdu->var_bindings()));
	return rv;
	}
%}

refine connection SNMP_Conn += {

	function proc_get_request(pdu: GetRequestPDU): bool
		%{
		if ( ! snmp_get_request )
			return false;

		zeek::BifEvent::enqueue_snmp_get_request(zeek_analyzer(),
		                                   zeek_analyzer()->Conn(),
		                                   ${pdu.header.is_orig},
		                                   build_hdr(${pdu.header}),
		                                   build_pdu(${pdu.pdu}));
		return true;
		%}

	function proc_get_next_request(pdu: GetNextRequestPDU): bool
		%{
		if ( ! snmp_get_next_request )
			return false;

		zeek::BifEvent::enqueue_snmp_get_next_request(zeek_analyzer(),
		                                        zeek_analyzer()->Conn(),
		                                        ${pdu.header.is_orig},
		                                        build_hdr(${pdu.header}),
		                                        build_pdu(${pdu.pdu}));
		return true;
		%}

	function proc_response(pdu: ResponsePDU): bool
		%{
		if ( ! snmp_response )
			return false;

		zeek::BifEvent::enqueue_snmp_response(zeek_analyzer(),
		                                zeek_analyzer()->Conn(),
		                                ${pdu.header.is_orig},
		                                build_hdr(${pdu.header}),
		                                build_pdu(${pdu.pdu}));
		return true;
		%}

	function proc_set_request(pdu: SetRequestPDU): bool
		%{
		if ( ! snmp_set_request )
			return false;

		zeek::BifEvent::enqueue_snmp_set_request(zeek_analyzer(),
		                                   zeek_analyzer()->Conn(),
		                                   ${pdu.header.is_orig},
		                                   build_hdr(${pdu.header}),
		                                   build_pdu(${pdu.pdu}));
		return true;
		%}

	function proc_trap(pdu: TrapPDU): bool
		%{
		if ( ! snmp_trap )
			return false;

		zeek::BifEvent::enqueue_snmp_trap(zeek_analyzer(),
		                            zeek_analyzer()->Conn(),
		                            ${pdu.header.is_orig},
		                            build_hdr(${pdu.header}),
		                            build_trap_pdu(${pdu}));
		return true;
		%}

	function proc_get_bulk_request(pdu: GetBulkRequestPDU): bool
		%{
		if ( ! snmp_get_bulk_request )
			return false;

		zeek::BifEvent::enqueue_snmp_get_bulk_request(zeek_analyzer(),
		                                        zeek_analyzer()->Conn(),
		                                        ${pdu.header.is_orig},
		                                        build_hdr(${pdu.header}),
		                                        build_bulk_pdu(${pdu}));
		return true;
		%}

	function proc_inform_request(pdu: InformRequestPDU): bool
		%{
		if ( ! snmp_inform_request )
			return false;

		zeek::BifEvent::enqueue_snmp_inform_request(zeek_analyzer(),
		                                      zeek_analyzer()->Conn(),
		                                      ${pdu.header.is_orig},
		                                      build_hdr(${pdu.header}),
		                                      build_pdu(${pdu.pdu}));
		return true;
		%}

	function proc_v2_trap(pdu: v2TrapPDU): bool
		%{
		if ( ! snmp_trapV2 )
			return false;

		zeek::BifEvent::enqueue_snmp_trapV2(zeek_analyzer(),
		                              zeek_analyzer()->Conn(),
		                              ${pdu.header.is_orig},
		                              build_hdr(${pdu.header}),
		                              build_pdu(${pdu.pdu}));
		return true;
		%}

	function proc_report(pdu: ReportPDU): bool
		%{
		if ( ! snmp_report )
			return false;

		zeek::BifEvent::enqueue_snmp_report(zeek_analyzer(),
		                              zeek_analyzer()->Conn(),
		                              ${pdu.header.is_orig},
		                              build_hdr(${pdu.header}),
		                              build_pdu(${pdu.pdu}));
		return true;
		%}

	function proc_unknown_version_header(rec: UnknownVersionHeader): bool
		%{
		if ( ! snmp_unknown_header_version )
			return false;

		zeek::BifEvent::enqueue_snmp_unknown_header_version(zeek_analyzer(),
		                                              zeek_analyzer()->Conn(),
		                                              ${rec.header.is_orig},
		                                              ${rec.header.version});
		return true;
		%}

	function proc_unknown_pdu(rec: UnknownPDU): bool
		%{
		if ( ! snmp_unknown_pdu )
			return false;

		zeek::BifEvent::enqueue_snmp_unknown_pdu(zeek_analyzer(),
		                                   zeek_analyzer()->Conn(),
		                                   ${rec.header.is_orig},
		                                   build_hdr(${rec.header}),
		                                   ${rec.tag});
		return true;
		%}

	function proc_unknown_scoped_pdu(rec: UnknownScopedPDU): bool
		%{
		if ( ! snmp_unknown_scoped_pdu )
			return false;

		zeek::BifEvent::enqueue_snmp_unknown_scoped_pdu(zeek_analyzer(),
		                                          zeek_analyzer()->Conn(),
		                                          ${rec.header.is_orig},
		                                          build_hdr(${rec.header}),
		                                          ${rec.tag});
		return true;
		%}

	function proc_encrypted_pdu(rec: EncryptedPDU): bool
		%{
		if ( ! snmp_encrypted_pdu )
			return false;

		zeek::BifEvent::enqueue_snmp_encrypted_pdu(zeek_analyzer(),
		                                     zeek_analyzer()->Conn(),
		                                     ${rec.header.is_orig},
		                                     build_hdr(${rec.header}));
		return true;
		%}

	function proc_header(rec: Header): bool
		%{
		if ( ! ${rec.is_orig} )
			zeek_analyzer()->AnalyzerConfirmation();

		if ( rec->unknown() )
			return false;

		return true;
		%}

	function proc_v3_header_data(rec: v3HeaderData): bool
		%{
		if ( rec->flags()->encoding()->content().length() == 1 )
			return true;

		zeek_analyzer()->AnalyzerViolation("Invalid v3 HeaderData msgFlags");
		return false;
		%}

	function check_tag(rec: ASN1EncodingMeta, expect: uint8): bool
		%{
		if ( rec->tag() == expect )
			return true;

		// Unwind now to stop parsing because it's definitely the
		// wrong protocol and parsing further could be expensive.
		// Upper layer of analyzer will catch and call AnalyzerViolation().
		throw binpac::Exception(zeek::util::fmt("Got ASN.1 tag %d, expect %d",
		                        rec->tag(), expect));
		return false;
		%}

	function check_int_width(rec: ASN1Integer): bool
		%{
		int len = rec->encoding()->content().length();

		if ( len <= 9 )
			// All integers use two's complement form, so an unsigned 64-bit
			// integer value can require 9 octets to encode if the highest
			// order bit is set.
			return true;

		throw binpac::Exception(zeek::util::fmt("ASN.1 integer width overflow: %d", len));
		return false;
		%}

	function check_int(rec: ASN1Integer): bool
		%{
		return check_tag(rec->encoding()->meta(), ASN1_INTEGER_TAG) &&
		       check_int_width(rec);
		%}
};

refine typeattr GetRequestPDU += &let {
	proc: bool = $context.connection.proc_get_request(this);
};
refine typeattr GetNextRequestPDU += &let {
	proc: bool = $context.connection.proc_get_next_request(this);
};
refine typeattr ResponsePDU += &let {
	proc: bool = $context.connection.proc_response(this);
};
refine typeattr SetRequestPDU += &let {
	proc: bool = $context.connection.proc_set_request(this);
};
refine typeattr TrapPDU += &let {
	proc: bool = $context.connection.proc_trap(this);
};
refine typeattr GetBulkRequestPDU += &let {
	proc: bool = $context.connection.proc_get_bulk_request(this);
};
refine typeattr InformRequestPDU += &let {
	proc: bool = $context.connection.proc_inform_request(this);
};
refine typeattr v2TrapPDU += &let {
	proc: bool = $context.connection.proc_v2_trap(this);
};
refine typeattr ReportPDU += &let {
	proc: bool = $context.connection.proc_report(this);
};

refine typeattr UnknownVersionHeader += &let {
	proc: bool = $context.connection.proc_unknown_version_header(this);
};
refine typeattr UnknownPDU += &let {
	proc: bool = $context.connection.proc_unknown_pdu(this);
};
refine typeattr UnknownScopedPDU += &let {
	proc: bool = $context.connection.proc_unknown_scoped_pdu(this);
};
refine typeattr EncryptedPDU += &let {
	proc: bool = $context.connection.proc_encrypted_pdu(this);
};

refine typeattr Header += &let {
	proc: bool = $context.connection.proc_header(this);
};

refine typeattr v3HeaderData += &let {
	proc: bool = $context.connection.proc_v3_header_data(this);
};

refine typeattr NetworkAddress += &let {
	valid: bool = $context.connection.check_tag(encoding.meta,
	                                            APP_IPADDRESS_TAG);
};
refine typeattr TimeTicks += &let {
	valid: bool = $context.connection.check_tag(asn1_integer.meta,
	                                            APP_TIMETICKS_TAG);
};

refine typeattr ASN1SequenceMeta += &let {
	valid: bool = $context.connection.check_tag(encoding,
	                                            ASN1_SEQUENCE_TAG);
};
refine typeattr ASN1Integer += &let {
	valid: bool = $context.connection.check_int(this);
};
refine typeattr ASN1OctetString += &let {
	valid: bool = $context.connection.check_tag(encoding.meta,
	                                            ASN1_OCTET_STRING_TAG);
};
refine typeattr ASN1ObjectIdentifier += &let {
	valid: bool = $context.connection.check_tag(encoding.meta,
	                                            ASN1_OBJECT_IDENTIFIER_TAG);
};
