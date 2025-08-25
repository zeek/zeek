# See the file "COPYING" in the main distribution directory for copyright.

@load base/frameworks/reporter
@load base/protocols/conn/removal-hooks

@load ./consts

module LDAP;

export {
  redef enum Log::ID += { LDAP_LOG, LDAP_SEARCH_LOG };

  ## TCP ports which should be considered for analysis.
  const ports_tcp = { 389/tcp, 3268/tcp } &redef;

  ## UDP ports which should be considered for analysis.
  const ports_udp = { 389/udp } &redef;

  ## Whether clear text passwords are captured or not.
  option default_capture_password = F;

  ## Whether to log LDAP search attributes or not.
  option default_log_search_attributes = F;

  ## Default logging policy hook for LDAP_LOG.
  global log_policy: Log::PolicyHook;

  ## Default logging policy hook for LDAP_SEARCH_LOG.
  global log_policy_search: Log::PolicyHook;

  ## LDAP finalization hook.
  global finalize_ldap: Conn::RemovalHook;

  #############################################################################
  # This is the format of ldap.log (ldap operations minus search-related)
  # Each line represents a unique connection+message_id (requests/responses)
  type MessageInfo: record {
    # Timestamp for when the event happened.
    ts: time &log;

    # Unique ID for the connection.
    uid: conn_uid &log;

    # The connection's 4-tuple of endpoint addresses/ports.
    id: conn_id &log;

    # Message ID
    message_id: int &log &optional;

    # LDAP version
    version: int &log &optional;

    # Normalized operation (e.g., bind_request and bind_response to "bind")
    opcode: string &log &optional;

    # Result code
    result: string &log &optional;

    # Result diagnostic message
    diagnostic_message: string &log &optional;

    # Object
    object: string &log &optional;

    # Argument
    argument: string &log &optional;
  };

  #############################################################################
  # This is the format of ldap_search.log (search-related messages only)
  # Each line represents a unique connection+message_id (requests/responses)
  type SearchInfo: record {
    # Timestamp for when the event happened.
    ts: time &log;

    # Unique ID for the connection.
    uid: conn_uid &log;

    # The connection's 4-tuple of endpoint addresses/ports.
    id: conn_id &log;

    # Message ID
    message_id: int &log &optional;

    # sets of search scope and deref alias
    scope: string &log &optional;
    deref_aliases: string &log &optional;

    # Base search objects
    base_object: string &log &optional;

    # Number of results returned
    result_count: count &log &optional;

    # Result code of search operation
    result: string &log &optional;

    # Result diagnostic message
    diagnostic_message: string &log &optional;

    # A string representation of the search filter used in the query
    filter: string &log &optional;

    # A list of attributes that were returned in the search
    attributes: vector of string &log &optional;
  };

  type State: record {
    messages: table[int] of MessageInfo &optional;
    searches: table[int] of SearchInfo &optional;
  };

  # Event that can be handled to access the ldap record as it is sent on
  # to the logging framework.
  global log_ldap: event(rec: LDAP::MessageInfo);
  global log_ldap_search: event(rec: LDAP::SearchInfo);
}

redef record connection += {
  ldap: State &optional;
};

redef likely_server_ports += { LDAP::ports_tcp, LDAP::ports_udp };

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
event zeek_init() &priority=5 {
  Analyzer::register_for_ports(Analyzer::ANALYZER_LDAP_TCP, LDAP::ports_tcp);
  Analyzer::register_for_ports(Analyzer::ANALYZER_LDAP_UDP, LDAP::ports_udp);

  Log::create_stream(LDAP::LDAP_LOG, Log::Stream($columns=MessageInfo, $ev=log_ldap, $path="ldap", $policy=log_policy));
  Log::create_stream(LDAP::LDAP_SEARCH_LOG, Log::Stream($columns=SearchInfo, $ev=log_ldap_search, $path="ldap_search", $policy=log_policy_search));
}

#############################################################################
function set_session(c: connection, message_id: int, opcode: LDAP::ProtocolOpcode) {

  if (! c?$ldap ) {
    c$ldap = State();
    Conn::register_removal_hook(c, finalize_ldap);
  }

  if (! c$ldap?$messages )
    c$ldap$messages = table();

  if (! c$ldap?$searches )
    c$ldap$searches = table();

  if ((opcode in OPCODES_SEARCH) && (message_id !in c$ldap$searches)) {
    c$ldap$searches[message_id] = SearchInfo($ts=network_time(),
                                             $uid=c$uid,
                                             $id=c$id,
                                             $message_id=message_id,
                                             $result_count=0);

  } else if ((opcode !in OPCODES_SEARCH) && (message_id !in c$ldap$messages)) {
    c$ldap$messages[message_id] = MessageInfo($ts=network_time(),
                                              $uid=c$uid,
                                              $id=c$id,
                                              $message_id=message_id);
  }
}

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

    local sm = c$ldap$searches[message_id];

    if ( result != LDAP::ResultCode_Undef ) {
      local sresult_str = RESULT_CODES[result];
      if ( sm?$result && sm$result != sresult_str ) {
        Reporter::conn_weird("LDAP_search_result_change", c,
                             fmt("%s: %s -> %s", message_id, sm$result, sresult_str), "LDAP");
      }

      sm$result = sresult_str;
    }

    if ( diagnostic_message != "" ) {
      if ( sm?$diagnostic_message && sm$diagnostic_message != diagnostic_message ) {
        Reporter::conn_weird("LDAP_search_diagnostic_message_change", c,
                             fmt("%s: %s -> %s", message_id, sm$diagnostic_message, diagnostic_message), "LDAP");
      }

      sm$diagnostic_message = diagnostic_message;
    }

    Log::write(LDAP::LDAP_SEARCH_LOG, sm);
    delete c$ldap$searches[message_id];

  } else if (opcode !in OPCODES_SEARCH) {  # search is handled via LDAP::search_request()
    set_session(c, message_id, opcode);

    local m = c$ldap$messages[message_id];

    local opcode_str = PROTOCOL_OPCODES[opcode];

    # bind request is explicitly handled via LDAP::bind_request() and
    # can assume we have a more specific m$opcode set.
    if ( opcode_str != "bind" ) {
      if ( m?$opcode && opcode_str != m$opcode ) {
        Reporter::conn_weird("LDAP_message_opcode_change", c,
                             fmt("%s: %s -> %s", message_id, m$opcode, opcode_str), "LDAP");
      }

      m$opcode = opcode_str;
    } else if ( ! m?$opcode ) {
      # This can happen if we see a bind response before the bind request.
      Reporter::conn_weird("LDAP_bind_without_opcode", c, fmt("%s: %s", message_id, opcode_str), "LDAP");
      m$opcode = opcode_str;
    }

    if ( result != LDAP::ResultCode_Undef ) {
      local result_str = RESULT_CODES[result];
      if ( m?$result && m$result != result_str ) {
        Reporter::conn_weird("LDAP_message_result_change", c,
                             fmt("%s: %s -> %s", message_id, m$result, result_str), "LDAP");
      }

      m$result = result_str;
    }

    if ( diagnostic_message != "" ) {
      if ( m?$diagnostic_message && diagnostic_message != m$diagnostic_message ) {
        Reporter::conn_weird("LDAP_message_diagnostic_message_change", c,
                             fmt("%s: %s -> %s", message_id, m$diagnostic_message, diagnostic_message), "LDAP");
      }

      m$diagnostic_message = diagnostic_message;
    }

    if ( object != "" ) {
      if ( m?$object && m$object != object ) {
        Reporter::conn_weird("LDAP_message_object_change", c,
                             fmt("%s: %s -> %s", message_id, m$object, object), "LDAP");
      }

      m$object = object;

      if ( opcode == LDAP::ProtocolOpcode_EXTENDED_REQUEST )
        m$object += fmt(" (%s)", EXTENDED_REQUESTS[object]);
    }

    if ( argument != "" ) {
      if ( m$opcode == BIND_SIMPLE && ! default_capture_password )
        argument = "REDACTED";

      if ( m?$argument && m$argument != argument ) {
        Reporter::conn_weird("LDAP_message_argument_change", c,
                             fmt("%s: %s -> %s", message_id, m$argument, argument), "LDAP");
      }

      m$argument = argument;
    }

    if (opcode in OPCODES_FINISHED) {
      Log::write(LDAP::LDAP_LOG, m);
      delete c$ldap$messages[message_id];
    }
  }
}

#############################################################################
event LDAP::search_request(c: connection,
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

  local sm = c$ldap$searches[message_id];

  if ( scope != LDAP::SearchScope_Undef ) {
    local scope_str = SEARCH_SCOPES[scope];
    if ( sm?$scope && sm$scope != scope_str ) {
      Reporter::conn_weird("LDAP_search_scope_change", c,
                           fmt("%s: %s -> %s", message_id, sm$scope, scope_str), "LDAP");
    }

    sm$scope = scope_str;
  }

  if ( deref != LDAP::SearchDerefAlias_Undef ) {
    local deref_aliases_str = SEARCH_DEREF_ALIASES[deref];
    if ( sm?$deref_aliases && sm$deref_aliases != deref_aliases_str ) {
      Reporter::conn_weird("LDAP_search_deref_aliases_change", c,
                           fmt("%s: %s -> %s", message_id, sm$deref_aliases, deref_aliases_str), "LDAP");
    }

    sm$deref_aliases = deref_aliases_str;
  }

  if ( base_object != "" ) {
    if ( sm?$base_object && sm$base_object != base_object ) {
      Reporter::conn_weird("LDAP_search_base_object_change", c,
                           fmt("%s: %s -> %s", message_id, sm$base_object, base_object), "LDAP");
    }

    sm$base_object = base_object;
  }

  if ( sm?$filter && sm$filter != filter )
      Reporter::conn_weird("LDAP_search_filter_change", c,
                           fmt("%s: %s -> %s", message_id, sm$filter, filter), "LDAP");

  sm$filter = filter;

  if ( default_log_search_attributes ) {
    if ( sm?$attributes && cat(sm$attributes) != cat(attributes) ) {
      Reporter::conn_weird("LDAP_search_attributes_change", c,
                           fmt("%s: %s -> %s", message_id, sm$attributes, attributes), "LDAP");
    }

    sm$attributes = attributes;
  }
}

#############################################################################
event LDAP::search_result_entry(c: connection,
                                message_id: int,
                                object_name: string) {

  set_session(c, message_id, LDAP::ProtocolOpcode_SEARCH_RESULT_ENTRY);

  c$ldap$searches[message_id]$result_count += 1;
}

#############################################################################
event LDAP::bind_request(c: connection,
                         message_id: int,
                         version: int,
                         name: string,
                         authType: LDAP::BindAuthType,
                         authInfo: string) {
  set_session(c, message_id, LDAP::ProtocolOpcode_BIND_REQUEST);

  local m = c$ldap$messages[message_id];

  if ( ! m?$version )
    m$version = version;

  # Getting herre, we don't expect the LDAP opcode to be set at all
  # and it'll be overwritten below.
  if ( m?$opcode )
    Reporter::conn_weird("LDAP_bind_opcode_already_set", c, m$opcode, "LDAP");

  switch ( authType ) {
  case LDAP::BindAuthType_BIND_AUTH_SIMPLE:
    m$opcode = BIND_SIMPLE;
    break;
  case LDAP::BindAuthType_BIND_AUTH_SASL:
    m$opcode = BIND_SASL;
    break;
  case LDAP::BindAuthType_SICILY_NEGOTIATE:
    m$opcode = BIND_SICILY_NEGOTIATE;
    break;
  case LDAP::BindAuthType_SICILY_RESPONSE:
    m$opcode = BIND_SICILY_RESPONSE;
    break;
  default:
    Reporter::conn_weird("LDAP_unknown_auth_type", c, cat(authType), "LDAP");
    m$opcode = cat(authType);
    break;
  }
}

#############################################################################
hook finalize_ldap(c: connection) {
  # log any "pending" unlogged LDAP messages/searches

  if ( c$ldap?$messages && (|c$ldap$messages| > 0) ) {
    for ( [mid], m in c$ldap$messages ) {
      if (mid > 0)
        Log::write(LDAP::LDAP_LOG, m);
    }
    delete c$ldap$messages;
  }

  if ( c$ldap?$searches && (|c$ldap$searches| > 0) ) {
    for ( [mid], s in c$ldap$searches ) {
      if (mid > 0) {
        Log::write(LDAP::LDAP_SEARCH_LOG, s);
      }
    }
    delete c$ldap$searches;
  }

}
