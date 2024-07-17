module LDAP;

export {
	const PROTOCOL_OPCODES = { [ LDAP::ProtocolOpcode_BIND_REQUEST ] = "bind", [
	    LDAP::ProtocolOpcode_BIND_RESPONSE ] = "bind", [
	    LDAP::ProtocolOpcode_UNBIND_REQUEST ] = "unbind", [
	    LDAP::ProtocolOpcode_SEARCH_REQUEST ] = "search", [
	    LDAP::ProtocolOpcode_SEARCH_RESULT_ENTRY ] = "search", [
	    LDAP::ProtocolOpcode_SEARCH_RESULT_DONE ] = "search", [
	    LDAP::ProtocolOpcode_MODIFY_REQUEST ] = "modify", [
	    LDAP::ProtocolOpcode_MODIFY_RESPONSE ] = "modify", [
	    LDAP::ProtocolOpcode_ADD_REQUEST ] = "add", [
	    LDAP::ProtocolOpcode_ADD_RESPONSE ] = "add", [
	    LDAP::ProtocolOpcode_DEL_REQUEST ] = "delete", [
	    LDAP::ProtocolOpcode_DEL_RESPONSE ] = "delete", [
	    LDAP::ProtocolOpcode_MOD_DN_REQUEST ] = "modify", [
	    LDAP::ProtocolOpcode_MOD_DN_RESPONSE ] = "modify", [
	    LDAP::ProtocolOpcode_COMPARE_REQUEST ] = "compare", [
	    LDAP::ProtocolOpcode_COMPARE_RESPONSE ] = "compare", [
	    LDAP::ProtocolOpcode_ABANDON_REQUEST ] = "abandon", [
	    LDAP::ProtocolOpcode_SEARCH_RESULT_REFERENCE ] = "search", [
	    LDAP::ProtocolOpcode_EXTENDED_REQUEST ] = "extended", [
	    LDAP::ProtocolOpcode_EXTENDED_RESPONSE ] = "extended", [
	    LDAP::ProtocolOpcode_INTERMEDIATE_RESPONSE ] = "intermediate" }
	    &default="unknown";

	const BIND_SIMPLE = "bind simple";
	const BIND_SASL = "bind SASL";

	const RESULT_CODES = { [ LDAP::ResultCode_SUCCESS ] = "success", [
	    LDAP::ResultCode_OPERATIONS_ERROR ] = "operations error", [
	    LDAP::ResultCode_PROTOCOL_ERROR ] = "protocol error", [
	    LDAP::ResultCode_TIME_LIMIT_EXCEEDED ] = "time limit exceeded", [
	    LDAP::ResultCode_SIZE_LIMIT_EXCEEDED ] = "size limit exceeded", [
	    LDAP::ResultCode_COMPARE_FALSE ] = "compare false", [
	    LDAP::ResultCode_COMPARE_TRUE ] = "compare true", [
	    LDAP::ResultCode_AUTH_METHOD_NOT_SUPPORTED ] =
	    "auth method not supported", [
	    LDAP::ResultCode_STRONGER_AUTH_REQUIRED ] =
	    "stronger auth required", [ LDAP::ResultCode_PARTIAL_RESULTS ] =
	    "partial results", [ LDAP::ResultCode_REFERRAL ] = "referral", [
	    LDAP::ResultCode_ADMIN_LIMIT_EXCEEDED ] = "admin limit exceeded", [
	    LDAP::ResultCode_UNAVAILABLE_CRITICAL_EXTENSION ] =
	    "unavailable critical extension", [
	    LDAP::ResultCode_CONFIDENTIALITY_REQUIRED ] =
	    "confidentiality required", [ LDAP::ResultCode_SASL_BIND_IN_PROGRESS ] =
	    "SASL bind in progress", [ LDAP::ResultCode_NO_SUCH_ATTRIBUTE ] =
	    "no such attribute", [ LDAP::ResultCode_UNDEFINED_ATTRIBUTE_TYPE ] =
	    "undefined attribute type", [
	    LDAP::ResultCode_INAPPROPRIATE_MATCHING ] =
	    "inappropriate matching", [ LDAP::ResultCode_CONSTRAINT_VIOLATION ] =
	    "constraint violation", [ LDAP::ResultCode_ATTRIBUTE_OR_VALUE_EXISTS ] =
	    "attribute or value exists", [
	    LDAP::ResultCode_INVALID_ATTRIBUTE_SYNTAX ] =
	    "invalid attribute syntax", [ LDAP::ResultCode_NO_SUCH_OBJECT ] =
	    "no such object", [ LDAP::ResultCode_ALIAS_PROBLEM ] =
	    "alias problem", [ LDAP::ResultCode_INVALID_DNSYNTAX ] =
	    "invalid DN syntax", [ LDAP::ResultCode_ALIAS_DEREFERENCING_PROBLEM ] =
	    "alias dereferencing problem", [
	    LDAP::ResultCode_INAPPROPRIATE_AUTHENTICATION ] =
	    "inappropriate authentication", [
	    LDAP::ResultCode_INVALID_CREDENTIALS ] = "invalid credentials", [
	    LDAP::ResultCode_INSUFFICIENT_ACCESS_RIGHTS ] =
	    "insufficient access rights", [ LDAP::ResultCode_BUSY ] = "busy", [
	    LDAP::ResultCode_UNAVAILABLE ] = "unavailable", [
	    LDAP::ResultCode_UNWILLING_TO_PERFORM ] = "unwilling to perform", [
	    LDAP::ResultCode_LOOP_DETECT ] = "loop detect", [
	    LDAP::ResultCode_SORT_CONTROL_MISSING ] = "sort control missing", [
	    LDAP::ResultCode_OFFSET_RANGE_ERROR ] = "offset range error", [
	    LDAP::ResultCode_NAMING_VIOLATION ] = "naming violation", [
	    LDAP::ResultCode_OBJECT_CLASS_VIOLATION ] =
	    "object class violation", [ LDAP::ResultCode_NOT_ALLOWED_ON_NON_LEAF ] =
	    "not allowed on non-leaf", [ LDAP::ResultCode_NOT_ALLOWED_ON_RDN ] =
	    "not allowed on RDN", [ LDAP::ResultCode_ENTRY_ALREADY_EXISTS ] =
	    "entry already exists", [
	    LDAP::ResultCode_OBJECT_CLASS_MODS_PROHIBITED ] =
	    "object class mods prohibited", [ LDAP::ResultCode_RESULTS_TOO_LARGE ] =
	    "results too large", [ LDAP::ResultCode_AFFECTS_MULTIPLE_DSAS ] =
	    "affects multiple DSAs", [ LDAP::ResultCode_CONTROL_ERROR ] =
	    "control error", [ LDAP::ResultCode_OTHER ] = "other", [
	    LDAP::ResultCode_SERVER_DOWN ] = "server down", [
	    LDAP::ResultCode_LOCAL_ERROR ] = "local error", [
	    LDAP::ResultCode_ENCODING_ERROR ] = "encoding error", [
	    LDAP::ResultCode_DECODING_ERROR ] = "decoding error", [
	    LDAP::ResultCode_TIMEOUT ] = "timeout", [
	    LDAP::ResultCode_AUTH_UNKNOWN ] = "auth unknown", [
	    LDAP::ResultCode_FILTER_ERROR ] = "filter error", [
	    LDAP::ResultCode_USER_CANCELED ] = "user canceled", [
	    LDAP::ResultCode_PARAM_ERROR ] = "param error", [
	    LDAP::ResultCode_NO_MEMORY ] = "no memory", [
	    LDAP::ResultCode_CONNECT_ERROR ] = "connect error", [
	    LDAP::ResultCode_NOT_SUPPORTED ] = "not supported", [
	    LDAP::ResultCode_CONTROL_NOT_FOUND ] = "control not found", [
	    LDAP::ResultCode_NO_RESULTS_RETURNED ] = "no results returned", [
	    LDAP::ResultCode_MORE_RESULTS_TO_RETURN ] =
	    "more results to return", [ LDAP::ResultCode_CLIENT_LOOP ] =
	    "client loop", [ LDAP::ResultCode_REFERRAL_LIMIT_EXCEEDED ] =
	    "referral limit exceeded", [ LDAP::ResultCode_INVALID_RESPONSE ] =
	    "invalid response", [ LDAP::ResultCode_AMBIGUOUS_RESPONSE ] =
	    "ambiguous response", [ LDAP::ResultCode_TLS_NOT_SUPPORTED ] =
	    "TLS not supported", [ LDAP::ResultCode_INTERMEDIATE_RESPONSE ] =
	    "intermediate response", [ LDAP::ResultCode_UNKNOWN_TYPE ] =
	    "unknown type", [ LDAP::ResultCode_LCUP_INVALID_DATA ] =
	    "LCUP invalid data", [ LDAP::ResultCode_LCUP_UNSUPPORTED_SCHEME ] =
	    "LCUP unsupported scheme", [ LDAP::ResultCode_LCUP_RELOAD_REQUIRED ] =
	    "LCUP reload required", [ LDAP::ResultCode_CANCELED ] =
	    "canceled", [ LDAP::ResultCode_NO_SUCH_OPERATION ] =
	    "no such operation", [ LDAP::ResultCode_TOO_LATE ] = "too late", [
	    LDAP::ResultCode_CANNOT_CANCEL ] = "cannot cancel", [
	    LDAP::ResultCode_ASSERTION_FAILED ] = "assertion failed", [
	    LDAP::ResultCode_AUTHORIZATION_DENIED ] = "authorization denied" }
	    &default="unknown";

	const SEARCH_SCOPES = { [ LDAP::SearchScope_SEARCH_BASE ] = "base", [
	    LDAP::SearchScope_SEARCH_SINGLE ] = "single", [
	    LDAP::SearchScope_SEARCH_TREE ] = "tree",  } &default="unknown";

	const SEARCH_DEREF_ALIASES = { [ LDAP::SearchDerefAlias_DEREF_NEVER ] =
	    "never", [ LDAP::SearchDerefAlias_DEREF_IN_SEARCHING ] =
	    "searching", [ LDAP::SearchDerefAlias_DEREF_FINDING_BASE ] =
	    "finding", [ LDAP::SearchDerefAlias_DEREF_ALWAYS ] = "always",  }
	    &default="unknown";

	const EXTENDED_REQUESTS = {
	   # StartTLS, https://datatracker.ietf.org/doc/html/rfc4511#section-4.14.1
	   [ "1.3.6.1.4.1.1466.20037" ] = "StartTLS",
	   # whoami, https://datatracker.ietf.org/doc/html/rfc4532#section-2
	   [ "1.3.6.1.4.1.4203.1.11.3" ] = "whoami",
	} &default="unknown" &redef;
}
