# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

module LDAP;

export {
  redef enum Log::ID += { LDAP_LOG,
                          LDAP_SEARCH_LOG };

  ## Whether clear text passwords are captured or not.
  option default_capture_password = F;

  ## Whether to log LDAP search attributes or not.
  option default_log_search_attributes = F;

  ## Default logging policy hook for LDAP_LOG.
  global log_policy: Log::PolicyHook;

  ## Default logging policy hook for LDAP_SEARCH_LOG.
  global log_policy_search: Log::PolicyHook;

  #############################################################################
  # This is the format of ldap.log (ldap operations minus search-related)
  # Each line represents a unique connection+message_id (requests/responses)
  type Message: record {

    # Timestamp for when the event happened.
    ts: time &log;

    # Unique ID for the connection.
    uid: string &log;

    # The connection's 4-tuple of endpoint addresses/ports.
    id: conn_id &log;

    # transport protocol
    proto: string &log &optional;

    # Message ID
    message_id: int &log &optional;

    # LDAP version
    version: int &log &optional;

    # normalized operations (e.g., bind_request and bind_response to "bind")
    opcode: set[string] &log &optional;

    # Result code(s)
    result: set[string] &log &optional;

    # result diagnostic message(s)
    diagnostic_message: vector of string &log &optional;

    # object(s)
    object: vector of string &log &optional;

    # argument(s)
    argument: vector of string &log &optional;
  };

  #############################################################################
  # This is the format of ldap_search.log (search-related messages only)
  # Each line represents a unique connection+message_id (requests/responses)
  type Search: record {

    # Timestamp for when the event happened.
    ts: time &log;

    # Unique ID for the connection.
    uid: string &log;

    # The connection's 4-tuple of endpoint addresses/ports.
    id: conn_id &log;

    # transport protocol
    proto: string &log &optional;

    # Message ID
    message_id: int &log &optional;

    # sets of search scope and deref alias
    scope: set[string] &log &optional;
    deref: set[string] &log &optional;

    # base search objects
    base_object: vector of string &log &optional;

    # number of results returned
    result_count: count &log &optional;

    # Result code (s)
    result: set[string] &log &optional;

    # result diagnostic message(s)
    diagnostic_message: vector of string &log &optional;

    #  a string representation of the search filter used in the query
    filter: string &log &optional;

    # a list of attributes that were returned in the search
    attributes: vector of string &log &optional;
  };

  # Event that can be handled to access the ldap record as it is sent on
  # to the logging framework.
  global log_ldap: event(rec: LDAP::Message);
  global log_ldap_search: event(rec: LDAP::Search);

  # Event called for each LDAP message (either direction)
  global LDAP::message: event(c: connection,
                              message_id: int,
                              opcode: LDAP::ProtocolOpcode,
                              result: LDAP::ResultCode,
                              matched_dn: string,
                              diagnostic_message: string,
                              object: string,
                              argument: string);

  const PROTOCOL_OPCODES = {
    [LDAP::ProtocolOpcode_BIND_REQUEST] = "bind",
    [LDAP::ProtocolOpcode_BIND_RESPONSE] = "bind",
    [LDAP::ProtocolOpcode_UNBIND_REQUEST] = "unbind",
    [LDAP::ProtocolOpcode_SEARCH_REQUEST] = "search",
    [LDAP::ProtocolOpcode_SEARCH_RESULT_ENTRY] = "search",
    [LDAP::ProtocolOpcode_SEARCH_RESULT_DONE] = "search",
    [LDAP::ProtocolOpcode_MODIFY_REQUEST] = "modify",
    [LDAP::ProtocolOpcode_MODIFY_RESPONSE] = "modify",
    [LDAP::ProtocolOpcode_ADD_REQUEST] = "add",
    [LDAP::ProtocolOpcode_ADD_RESPONSE] = "add",
    [LDAP::ProtocolOpcode_DEL_REQUEST] = "delete",
    [LDAP::ProtocolOpcode_DEL_RESPONSE] = "delete",
    [LDAP::ProtocolOpcode_MOD_DN_REQUEST] = "modify",
    [LDAP::ProtocolOpcode_MOD_DN_RESPONSE] = "modify",
    [LDAP::ProtocolOpcode_COMPARE_REQUEST] = "compare",
    [LDAP::ProtocolOpcode_COMPARE_RESPONSE] = "compare",
    [LDAP::ProtocolOpcode_ABANDON_REQUEST] = "abandon",
    [LDAP::ProtocolOpcode_SEARCH_RESULT_REFERENCE] = "search",
    [LDAP::ProtocolOpcode_EXTENDED_REQUEST] = "extended",
    [LDAP::ProtocolOpcode_EXTENDED_RESPONSE] = "extended",
    [LDAP::ProtocolOpcode_INTERMEDIATE_RESPONSE] = "intermediate"
  } &default = "unknown";

  const BIND_SIMPLE = "bind simple";
  const BIND_SASL = "bind SASL";

  const RESULT_CODES = {
    [LDAP::ResultCode_SUCCESS] = "success",
    [LDAP::ResultCode_OPERATIONS_ERROR] = "operations error",
    [LDAP::ResultCode_PROTOCOL_ERROR] = "protocol error",
    [LDAP::ResultCode_TIME_LIMIT_EXCEEDED] = "time limit exceeded",
    [LDAP::ResultCode_SIZE_LIMIT_EXCEEDED] = "size limit exceeded",
    [LDAP::ResultCode_COMPARE_FALSE] = "compare false",
    [LDAP::ResultCode_COMPARE_TRUE] = "compare true",
    [LDAP::ResultCode_AUTH_METHOD_NOT_SUPPORTED] = "auth method not supported",
    [LDAP::ResultCode_STRONGER_AUTH_REQUIRED] = "stronger auth required",
    [LDAP::ResultCode_PARTIAL_RESULTS] = "partial results",
    [LDAP::ResultCode_REFERRAL] = "referral",
    [LDAP::ResultCode_ADMIN_LIMIT_EXCEEDED] = "admin limit exceeded",
    [LDAP::ResultCode_UNAVAILABLE_CRITICAL_EXTENSION] = "unavailable critical extension",
    [LDAP::ResultCode_CONFIDENTIALITY_REQUIRED] = "confidentiality required",
    [LDAP::ResultCode_SASL_BIND_IN_PROGRESS] = "SASL bind in progress",
    [LDAP::ResultCode_NO_SUCH_ATTRIBUTE] = "no such attribute",
    [LDAP::ResultCode_UNDEFINED_ATTRIBUTE_TYPE] = "undefined attribute type",
    [LDAP::ResultCode_INAPPROPRIATE_MATCHING] = "inappropriate matching",
    [LDAP::ResultCode_CONSTRAINT_VIOLATION] = "constraint violation",
    [LDAP::ResultCode_ATTRIBUTE_OR_VALUE_EXISTS] = "attribute or value exists",
    [LDAP::ResultCode_INVALID_ATTRIBUTE_SYNTAX] = "invalid attribute syntax",
    [LDAP::ResultCode_NO_SUCH_OBJECT] = "no such object",
    [LDAP::ResultCode_ALIAS_PROBLEM] = "alias problem",
    [LDAP::ResultCode_INVALID_DNSYNTAX] = "invalid DN syntax",
    [LDAP::ResultCode_ALIAS_DEREFERENCING_PROBLEM] = "alias dereferencing problem",
    [LDAP::ResultCode_INAPPROPRIATE_AUTHENTICATION] = "inappropriate authentication",
    [LDAP::ResultCode_INVALID_CREDENTIALS] = "invalid credentials",
    [LDAP::ResultCode_INSUFFICIENT_ACCESS_RIGHTS] = "insufficient access rights",
    [LDAP::ResultCode_BUSY] = "busy",
    [LDAP::ResultCode_UNAVAILABLE] = "unavailable",
    [LDAP::ResultCode_UNWILLING_TO_PERFORM] = "unwilling to perform",
    [LDAP::ResultCode_LOOP_DETECT] = "loop detect",
    [LDAP::ResultCode_SORT_CONTROL_MISSING] = "sort control missing",
    [LDAP::ResultCode_OFFSET_RANGE_ERROR] = "offset range error",
    [LDAP::ResultCode_NAMING_VIOLATION] = "naming violation",
    [LDAP::ResultCode_OBJECT_CLASS_VIOLATION] = "object class violation",
    [LDAP::ResultCode_NOT_ALLOWED_ON_NON_LEAF] = "not allowed on non-leaf",
    [LDAP::ResultCode_NOT_ALLOWED_ON_RDN] = "not allowed on RDN",
    [LDAP::ResultCode_ENTRY_ALREADY_EXISTS] = "entry already exists",
    [LDAP::ResultCode_OBJECT_CLASS_MODS_PROHIBITED] = "object class mods prohibited",
    [LDAP::ResultCode_RESULTS_TOO_LARGE] = "results too large",
    [LDAP::ResultCode_AFFECTS_MULTIPLE_DSAS] = "affects multiple DSAs",
    [LDAP::ResultCode_CONTROL_ERROR] = "control error",
    [LDAP::ResultCode_OTHER] = "other",
    [LDAP::ResultCode_SERVER_DOWN] = "server down",
    [LDAP::ResultCode_LOCAL_ERROR] = "local error",
    [LDAP::ResultCode_ENCODING_ERROR] = "encoding error",
    [LDAP::ResultCode_DECODING_ERROR] = "decoding error",
    [LDAP::ResultCode_TIMEOUT] = "timeout",
    [LDAP::ResultCode_AUTH_UNKNOWN] = "auth unknown",
    [LDAP::ResultCode_FILTER_ERROR] = "filter error",
    [LDAP::ResultCode_USER_CANCELED] = "user canceled",
    [LDAP::ResultCode_PARAM_ERROR] = "param error",
    [LDAP::ResultCode_NO_MEMORY] = "no memory",
    [LDAP::ResultCode_CONNECT_ERROR] = "connect error",
    [LDAP::ResultCode_NOT_SUPPORTED] = "not supported",
    [LDAP::ResultCode_CONTROL_NOT_FOUND] = "control not found",
    [LDAP::ResultCode_NO_RESULTS_RETURNED] = "no results returned",
    [LDAP::ResultCode_MORE_RESULTS_TO_RETURN] = "more results to return",
    [LDAP::ResultCode_CLIENT_LOOP] = "client loop",
    [LDAP::ResultCode_REFERRAL_LIMIT_EXCEEDED] = "referral limit exceeded",
    [LDAP::ResultCode_INVALID_RESPONSE] = "invalid response",
    [LDAP::ResultCode_AMBIGUOUS_RESPONSE] = "ambiguous response",
    [LDAP::ResultCode_TLS_NOT_SUPPORTED] = "TLS not supported",
    [LDAP::ResultCode_INTERMEDIATE_RESPONSE] = "intermediate response",
    [LDAP::ResultCode_UNKNOWN_TYPE] = "unknown type",
    [LDAP::ResultCode_LCUP_INVALID_DATA] = "LCUP invalid data",
    [LDAP::ResultCode_LCUP_UNSUPPORTED_SCHEME] = "LCUP unsupported scheme",
    [LDAP::ResultCode_LCUP_RELOAD_REQUIRED] = "LCUP reload required",
    [LDAP::ResultCode_CANCELED] = "canceled",
    [LDAP::ResultCode_NO_SUCH_OPERATION] = "no such operation",
    [LDAP::ResultCode_TOO_LATE] = "too late",
    [LDAP::ResultCode_CANNOT_CANCEL] = "cannot cancel",
    [LDAP::ResultCode_ASSERTION_FAILED] = "assertion failed",
    [LDAP::ResultCode_AUTHORIZATION_DENIED] = "authorization denied"
  } &default = "unknown";

  const SEARCH_SCOPES = {
    [LDAP::SearchScope_SEARCH_BASE] = "base",
    [LDAP::SearchScope_SEARCH_SINGLE] = "single",
    [LDAP::SearchScope_SEARCH_TREE] = "tree",
  } &default = "unknown";

  const SEARCH_DEREF_ALIASES = {
    [LDAP::SearchDerefAlias_DEREF_NEVER] = "never",
    [LDAP::SearchDerefAlias_DEREF_IN_SEARCHING] = "searching",
    [LDAP::SearchDerefAlias_DEREF_FINDING_BASE] = "finding",
    [LDAP::SearchDerefAlias_DEREF_ALWAYS] = "always",
  } &default = "unknown";
}

#############################################################################
global OPCODES_FINISHED: set[LDAP::ProtocolOpcode] = { LDAP::ProtocolOpcode_BIND_RESPONSE,
                                                       LDAP::ProtocolOpcode_UNBIND_REQUEST,
                                                       LDAP::ProtocolOpcode_SEARCH_RESULT_DONE,
                                                       LDAP::ProtocolOpcode_MODIFY_RESPONSE,
                                                       LDAP::ProtocolOpcode_ADD_RESPONSE,
                                                       LDAP::ProtocolOpcode_DEL_RESPONSE,
                                                       LDAP::ProtocolOpcode_MOD_DN_RESPONSE,
                                                       LDAP::ProtocolOpcode_COMPARE_RESPONSE,
                                                       LDAP::ProtocolOpcode_ABANDON_REQUEST,
                                                       LDAP::ProtocolOpcode_EXTENDED_RESPONSE };

global OPCODES_SEARCH: set[LDAP::ProtocolOpcode] = { LDAP::ProtocolOpcode_SEARCH_REQUEST,
                                                     LDAP::ProtocolOpcode_SEARCH_RESULT_ENTRY,
                                                     LDAP::ProtocolOpcode_SEARCH_RESULT_DONE,
                                                     LDAP::ProtocolOpcode_SEARCH_RESULT_REFERENCE };

#############################################################################
redef record connection += {
  ldap_proto: string &optional;
  ldap_messages: table[int] of Message &optional;
  ldap_searches: table[int] of Search &optional;
};

#############################################################################
event zeek_init() &priority=5 {
  Log::create_stream(LDAP::LDAP_LOG, [$columns=Message, $ev=log_ldap, $path="ldap", $policy=log_policy]);
  Log::create_stream(LDAP::LDAP_SEARCH_LOG, [$columns=Search, $ev=log_ldap_search, $path="ldap_search", $policy=log_policy_search]);
}

#############################################################################
function set_session(c: connection, message_id: int, opcode: LDAP::ProtocolOpcode) {

  if (! c?$ldap_messages )
    c$ldap_messages = table();

  if (! c?$ldap_searches )
    c$ldap_searches = table();

  if ((opcode in OPCODES_SEARCH) && (message_id !in c$ldap_searches)) {
    c$ldap_searches[message_id] = [$ts=network_time(),
                                   $uid=c$uid,
                                   $id=c$id,
                                   $message_id=message_id,
                                   $result_count=0];

  } else if ((opcode !in OPCODES_SEARCH) && (message_id !in c$ldap_messages)) {
    c$ldap_messages[message_id] = [$ts=network_time(),
                                   $uid=c$uid,
                                   $id=c$id,
                                   $message_id=message_id];
  }

}

#############################################################################
@if (Version::at_least("5.2.0"))
event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo) {
  if ( atype == Analyzer::ANALYZER_SPICY_LDAP_TCP ) {
    info$c$ldap_proto = "tcp";
  }
}
@else @if (Version::at_least("4.2.0"))
event analyzer_confirmation(c: connection, atype: AllAnalyzers::Tag, aid: count) {
@else
event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) {
@endif

  if ( atype == Analyzer::ANALYZER_SPICY_LDAP_TCP ) {
    c$ldap_proto = "tcp";
  }

}
@endif
#############################################################################
event LDAP::message(c: connection,
                    message_id: int,
                    opcode: LDAP::ProtocolOpcode,
                    result: LDAP::ResultCode,
                    matched_dn: string,
                    diagnostic_message: string,
                    object: string,
                    argument: string) {

  if (opcode == LDAP::ProtocolOpcode_SEARCH_RESULT_DONE) {
    set_session(c, message_id, opcode);

    if ( result != LDAP::ResultCode_Undef ) {
      if ( ! c$ldap_searches[message_id]?$result )
        c$ldap_searches[message_id]$result = set();
      add c$ldap_searches[message_id]$result[RESULT_CODES[result]];
    }

    if ( diagnostic_message != "" ) {
      if ( ! c$ldap_searches[message_id]?$diagnostic_message )
        c$ldap_searches[message_id]$diagnostic_message = vector();
      c$ldap_searches[message_id]$diagnostic_message += diagnostic_message;
    }

    if (( ! c$ldap_searches[message_id]?$proto ) && c?$ldap_proto)
      c$ldap_searches[message_id]$proto = c$ldap_proto;

    Log::write(LDAP::LDAP_SEARCH_LOG, c$ldap_searches[message_id]);
    delete c$ldap_searches[message_id];

  } else if (opcode !in OPCODES_SEARCH) {
    set_session(c, message_id, opcode);

    if ( ! c$ldap_messages[message_id]?$opcode )
      c$ldap_messages[message_id]$opcode = set();
    add c$ldap_messages[message_id]$opcode[PROTOCOL_OPCODES[opcode]];

    if ( result != LDAP::ResultCode_Undef ) {
      if ( ! c$ldap_messages[message_id]?$result )
        c$ldap_messages[message_id]$result = set();
      add c$ldap_messages[message_id]$result[RESULT_CODES[result]];
    }

    if ( diagnostic_message != "" ) {
      if ( ! c$ldap_messages[message_id]?$diagnostic_message )
        c$ldap_messages[message_id]$diagnostic_message = vector();
      c$ldap_messages[message_id]$diagnostic_message += diagnostic_message;
    }

    if ( object != "" ) {
      if ( ! c$ldap_messages[message_id]?$object )
        c$ldap_messages[message_id]$object = vector();
      c$ldap_messages[message_id]$object += object;
    }

    if ( argument != "" ) {
      if ( ! c$ldap_messages[message_id]?$argument )
        c$ldap_messages[message_id]$argument = vector();
      if ("bind simple" in c$ldap_messages[message_id]$opcode && !default_capture_password)
        c$ldap_messages[message_id]$argument += "REDACTED";
      else
        c$ldap_messages[message_id]$argument += argument;
    }

    if (opcode in OPCODES_FINISHED) {

      if ((BIND_SIMPLE in c$ldap_messages[message_id]$opcode) ||
          (BIND_SASL in c$ldap_messages[message_id]$opcode)) {
        # don't have both "bind" and "bind <method>" in the operations list
        delete c$ldap_messages[message_id]$opcode[PROTOCOL_OPCODES[LDAP::ProtocolOpcode_BIND_REQUEST]];
      }

      if (( ! c$ldap_messages[message_id]?$proto ) && c?$ldap_proto)
        c$ldap_messages[message_id]$proto = c$ldap_proto;

      Log::write(LDAP::LDAP_LOG, c$ldap_messages[message_id]);
      delete c$ldap_messages[message_id];
    }
  }

}

#############################################################################
event LDAP::searchreq(c: connection,
                      message_id: int,
                      base_object: string,
                      scope: LDAP::SearchScope,
                      deref: LDAP::SearchDerefAlias,
                      size_limit: int,
                      time_limit: int,
                      types_only: bool,
                      filter: string,
                      attributes: vector of string) {

  set_session(c, message_id, LDAP::ProtocolOpcode_SEARCH_REQUEST);

  if ( scope != LDAP::SearchScope_Undef ) {
    if ( ! c$ldap_searches[message_id]?$scope )
      c$ldap_searches[message_id]$scope = set();
    add c$ldap_searches[message_id]$scope[SEARCH_SCOPES[scope]];
  }

  if ( deref != LDAP::SearchDerefAlias_Undef ) {
    if ( ! c$ldap_searches[message_id]?$deref )
      c$ldap_searches[message_id]$deref = set();
    add c$ldap_searches[message_id]$deref[SEARCH_DEREF_ALIASES[deref]];
  }

  if ( base_object != "" ) {
    if ( ! c$ldap_searches[message_id]?$base_object )
      c$ldap_searches[message_id]$base_object = vector();
    c$ldap_searches[message_id]$base_object += base_object;
  }
  c$ldap_searches[message_id]$filter = filter;

  if ( default_log_search_attributes ) {
    c$ldap_searches[message_id]$attributes = attributes;
  }
}

#############################################################################
event LDAP::searchres(c: connection,
                      message_id: int,
                      object_name: string) {

  set_session(c, message_id, LDAP::ProtocolOpcode_SEARCH_RESULT_ENTRY);

  c$ldap_searches[message_id]$result_count += 1;
}

#############################################################################
event LDAP::bindreq(c: connection,
                    message_id: int,
                    version: int,
                    name: string,
                    authType: LDAP::BindAuthType,
                    authInfo: string) {

  set_session(c, message_id, LDAP::ProtocolOpcode_BIND_REQUEST);

  if ( ! c$ldap_messages[message_id]?$version )
    c$ldap_messages[message_id]$version = version;

  if ( ! c$ldap_messages[message_id]?$opcode )
    c$ldap_messages[message_id]$opcode = set();

  if (authType == LDAP::BindAuthType_BIND_AUTH_SIMPLE) {
    add c$ldap_messages[message_id]$opcode[BIND_SIMPLE];
  } else if (authType == LDAP::BindAuthType_BIND_AUTH_SASL) {
    add c$ldap_messages[message_id]$opcode[BIND_SASL];
  }

}

#############################################################################
event connection_state_remove(c: connection) {

  # log any "pending" unlogged LDAP messages/searches

  if ( c?$ldap_messages && (|c$ldap_messages| > 0) ) {
    for ( [mid], m in c$ldap_messages ) {
      if (mid > 0) {

        if ((BIND_SIMPLE in m$opcode) || (BIND_SASL in m$opcode)) {
          # don't have both "bind" and "bind <method>" in the operations list
          delete m$opcode[PROTOCOL_OPCODES[LDAP::ProtocolOpcode_BIND_REQUEST]];
        }

        if (( ! m?$proto ) && c?$ldap_proto)
          m$proto = c$ldap_proto;

        Log::write(LDAP::LDAP_LOG, m);
      }
    }
    delete c$ldap_messages;
  }

  if ( c?$ldap_searches && (|c$ldap_searches| > 0) ) {
    for ( [mid], s in c$ldap_searches ) {
      if (mid > 0) {

        if (( ! s?$proto ) && c?$ldap_proto)
          s$proto = c$ldap_proto;

        Log::write(LDAP::LDAP_SEARCH_LOG, s);
      }
    }
    delete c$ldap_searches;
  }

}
