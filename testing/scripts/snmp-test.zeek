
function format_snmp_val(tag: count, s: string): string
	{
	return fmt("    value (tag=0x%02x): %s", tag, s);
	}

function print_snmp_value(val: SNMP::ObjectValue)
	{
	switch ( val$tag ) {
	case SNMP::OBJ_OID_TAG:
		print format_snmp_val(val$tag, fmt("%s", val$oid));
		break;

	case SNMP::OBJ_INTEGER_TAG:
		print format_snmp_val(val$tag, fmt("%s", val$signed));
		break;

	case SNMP::OBJ_COUNTER32_TAG,
	     SNMP::OBJ_UNSIGNED32_TAG,
	     SNMP::OBJ_TIMETICKS_TAG,
	     SNMP::OBJ_COUNTER64_TAG:
		print format_snmp_val(val$tag, fmt("%s", val$unsigned));
		break;

	case SNMP::OBJ_IPADDRESS_TAG:
		print format_snmp_val(val$tag, fmt("%s", val$address));
		break;

	case SNMP::OBJ_OCTETSTRING_TAG,
         SNMP::OBJ_OPAQUE_TAG:
		print format_snmp_val(val$tag, fmt("%s", val$octets));
		break;

	case SNMP::OBJ_UNSPECIFIED_TAG:
		print format_snmp_val(val$tag, fmt("%s", "<unspecified>"));
		break;

	case SNMP::OBJ_NOSUCHOBJECT_TAG:
		print format_snmp_val(val$tag, fmt("%s", "<no such object>"));
		break;

	case SNMP::OBJ_NOSUCHINSTANCE_TAG:
		print format_snmp_val(val$tag, fmt("%s", "<no such instance>"));
		break;

	case SNMP::OBJ_ENDOFMIBVIEW_TAG:
		print format_snmp_val(val$tag, fmt("%s", "<end of mib view>"));
		break;

	default:
		print format_snmp_val(val$tag, "<unknown>");
		break;
	}
	}

function print_snmp_binding(binding: SNMP::Binding)
	{
	print fmt("    oid: %s", binding$oid);
	print_snmp_value(binding$value);
	}

function print_snmp_bindings(bindings: SNMP::Bindings)
	{
	for ( i in bindings )
		print_snmp_binding(bindings[i]);
	}

function print_snmp_pdu(pdu: SNMP::PDU)
	{
	print fmt("    request_id: %s", pdu$request_id);
	print fmt("    error_stat: %s", pdu$error_status);
	print fmt("    error_idx:  %s", pdu$error_index);
	print_snmp_bindings(pdu$bindings);
	}

function print_snmp_trap_pdu(pdu: SNMP::TrapPDU)
	{
	print fmt("    enterprise:    %s", pdu$enterprise);
	print fmt("    agent:         %s", pdu$agent);
	print fmt("    generic_trap:  %s", pdu$generic_trap);
	print fmt("    specific_trap: %s", pdu$specific_trap);
	print fmt("    time_stamp:    %s", pdu$time_stamp);
	print_snmp_bindings(pdu$bindings);
	}

function print_snmp_bulk_pdu(pdu: SNMP::BulkPDU)
	{
	print fmt("    request_id:      %s", pdu$request_id);
	print fmt("    non_repeaters:   %s", pdu$non_repeaters);
	print fmt("    max_repetitions: %s", pdu$max_repetitions);
	print_snmp_bindings(pdu$bindings);
	}

function print_snmp_conn(c: connection, is_orig: bool)
	{
	print fmt("  %s", c$id);
	print fmt("  is_orig: %s", is_orig);
	}

function print_snmp_header(header: SNMP::Header)
	{
	switch ( header$version ) {
	case 0:
		print fmt("  %s", header$v1);
		break;

	case 1:
		print fmt("  %s", header$v2);
		break;

	case 3:
		print fmt("  %s", header$v3);
		break;

	default:
		break;
	}
	}

function print_snmp(msg: string, c: connection, is_orig: bool,
                    header: SNMP::Header, pdu: SNMP::PDU)
	{
	print msg;
	print_snmp_conn(c, is_orig);
	print_snmp_header(header);
	print_snmp_pdu(pdu);
	}

event snmp_get_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
	{
	print_snmp("snmp_get_request", c, is_orig, header, pdu);
	}

event snmp_get_next_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
	{
	print_snmp("snmp_get_request", c, is_orig, header, pdu);
	}

event snmp_response(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
	{
	print_snmp("snmp_response", c, is_orig, header, pdu);
	}

event snmp_set_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
	{
	print_snmp("snmp_set_request", c, is_orig, header, pdu);
	}

event snmp_trap(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::TrapPDU)
	{
	print "snmp_trap";
	print_snmp_conn(c, is_orig);
	print_snmp_header(header);
	print_snmp_trap_pdu(pdu);
	}

event snmp_get_bulk_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::BulkPDU)
	{
	print "snmp_get_bulk_request";
	print_snmp_conn(c, is_orig);
	print_snmp_header(header);
	print_snmp_bulk_pdu(pdu);
	}

event snmp_inform_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
	{
	print_snmp("snmp_inform_request", c, is_orig, header, pdu);
	}

event snmp_trapV2(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
	{
	print_snmp("snmp_trapv2", c, is_orig, header, pdu);
	}

event snmp_report(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
	{
	print_snmp("snmp_report", c, is_orig, header, pdu);
	}

event snmp_unknown_pdu(c: connection, is_orig: bool, header: SNMP::Header, tag: count)
	{
	print "snmp_unknown_pdu";
	print_snmp_conn(c, is_orig);
	print_snmp_header(header);
	print fmt("  tag: %s", tag);
	}

event snmp_unknown_scoped_pdu(c: connection, is_orig: bool, header: SNMP::Header, tag: count)
	{
	print "snmp_unknown_scoped_pdu";
	print_snmp_conn(c, is_orig);
	print_snmp_header(header);
	print fmt("  tag: %s", tag);
	}

event snmp_encrypted_pdu(c: connection, is_orig: bool, header: SNMP::Header)
	{
	print "snmp_encrypted_pdu";
	print_snmp_conn(c, is_orig);
	print_snmp_header(header);
	}

event snmp_unknown_header_version(c: connection, is_orig: bool, version: count)
	{
	print "snmp_unknown_header_version";
	print_snmp_conn(c, is_orig);
	print fmt("  version %s", version);
	}
