# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

@load base/protocols/conn/removal-hooks

@load ./consts

module LDAP;

export {
  redef enum Log::ID += { LDAP_LOG,
                          LDAP_SEARCH_LOG };

  ## TCP ports which should be considered for analysis.
  const ports_tcp = { 389/tcp, 3268/tcp } &redef;

  ## UDP ports which should be considered for analysis.
  const ports_udp = { 389/udp } &redef;

  redef likely_server_ports += { LDAP::ports_tcp, LDAP::ports_udp };

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
  type MessageInfo: record {
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
    opcodes: set[string] &log &optional;

    # Result code(s)
    results: set[string] &log &optional;

    # result diagnostic message(s)
    diagnostic_messages: vector of string &log &optional;

    # object(s)
    objects: vector of string &log &optional;

    # argument(s)
    arguments: vector of string &log &optional;
  };

  #############################################################################
  # This is the format of ldap_search.log (search-related messages only)
  # Each line represents a unique connection+message_id (requests/responses)
  type SearchInfo: record {
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
    scopes: set[string] &log &optional;
    derefs: set[string] &log &optional;

    # base search objects
    base_objects: vector of string &log &optional;

    # number of results returned
    result_count: count &log &optional;

    # Result code (s)
    results: set[string] &log &optional;

    # result diagnostic message(s)
    diagnostic_messages: vector of string &log &optional;

    #  a string representation of the search filter used in the query
    filter: string &log &optional;

    # a list of attributes that were returned in the search
    attributes: vector of string &log &optional;
  };

  # Event that can be handled to access the ldap record as it is sent on
  # to the logging framework.
  global log_ldap: event(rec: LDAP::MessageInfo);
  global log_ldap_search: event(rec: LDAP::SearchInfo);

  # Event called for each LDAP message (either direction)
  global LDAP::message: event(c: connection,
                              message_id: int,
                              opcode: LDAP::ProtocolOpcode,
                              result: LDAP::ResultCode,
                              matched_dn: string,
                              diagnostic_message: string,
                              object: string,
                              argument: string);
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
  ldap_messages: table[int] of MessageInfo &optional;
  ldap_searches: table[int] of SearchInfo &optional;
};

#############################################################################
event zeek_init() &priority=5 {
  Analyzer::register_for_ports(Analyzer::ANALYZER_LDAP_TCP, LDAP::ports_tcp);
  Analyzer::register_for_ports(Analyzer::ANALYZER_LDAP_UDP, LDAP::ports_udp);

  Log::create_stream(LDAP::LDAP_LOG, [$columns=MessageInfo, $ev=log_ldap, $path="ldap", $policy=log_policy]);
  Log::create_stream(LDAP::LDAP_SEARCH_LOG, [$columns=SearchInfo, $ev=log_ldap_search, $path="ldap_search", $policy=log_policy_search]);
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
  if ( atype == Analyzer::ANALYZER_LDAP_TCP ) {
    info$c$ldap_proto = "tcp";
  }
}
@else @if (Version::at_least("4.2.0"))
event analyzer_confirmation(c: connection, atype: AllAnalyzers::Tag, aid: count) {
@else
event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) {
@endif

  if ( atype == Analyzer::ANALYZER_LDAP_TCP ) {
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

    local searches = c$ldap_searches[message_id];

    if ( result != LDAP::ResultCode_Undef ) {
      if ( ! searches?$results )
        searches$results = set();
      add searches$results[RESULT_CODES[result]];
    }

    if ( diagnostic_message != "" ) {
      if ( ! searches?$diagnostic_messages )
        searches$diagnostic_messages = vector();
      searches$diagnostic_messages += diagnostic_message;
    }

    if (( ! searches?$proto ) && c?$ldap_proto)
      searches$proto = c$ldap_proto;

    Log::write(LDAP::LDAP_SEARCH_LOG, searches);
    delete c$ldap_searches[message_id];

  } else if (opcode !in OPCODES_SEARCH) {
    set_session(c, message_id, opcode);

    local messages = c$ldap_messages[message_id];

    if ( ! messages?$opcodes )
      messages$opcodes = set();
    add messages$opcodes[PROTOCOL_OPCODES[opcode]];

    if ( result != LDAP::ResultCode_Undef ) {
      if ( ! messages?$results )
        messages$results = set();
      add messages$results[RESULT_CODES[result]];
    }

    if ( diagnostic_message != "" ) {
      if ( ! messages?$diagnostic_messages )
        messages$diagnostic_messages = vector();
      messages$diagnostic_messages += diagnostic_message;
    }

    if ( object != "" ) {
      if ( ! messages?$objects )
        messages$objects = vector();
      messages$objects += object;
    }

    if ( argument != "" ) {
      if ( ! messages?$arguments )
        messages$arguments = vector();
      if ("bind simple" in messages$opcodes && !default_capture_password)
        messages$arguments += "REDACTED";
      else
        messages$arguments += argument;
    }

    if (opcode in OPCODES_FINISHED) {

      if ((BIND_SIMPLE in messages$opcodes) ||
          (BIND_SASL in messages$opcodes)) {
        # don't have both "bind" and "bind <method>" in the operations list
        delete messages$opcodes[PROTOCOL_OPCODES[LDAP::ProtocolOpcode_BIND_REQUEST]];
      }

      if (( ! messages?$proto ) && c?$ldap_proto)
        messages$proto = c$ldap_proto;

      Log::write(LDAP::LDAP_LOG, messages);
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
    if ( ! c$ldap_searches[message_id]?$scopes )
      c$ldap_searches[message_id]$scopes = set();
    add c$ldap_searches[message_id]$scopes[SEARCH_SCOPES[scope]];
  }

  if ( deref != LDAP::SearchDerefAlias_Undef ) {
    if ( ! c$ldap_searches[message_id]?$derefs )
      c$ldap_searches[message_id]$derefs = set();
    add c$ldap_searches[message_id]$derefs[SEARCH_DEREF_ALIASES[deref]];
  }

  if ( base_object != "" ) {
    if ( ! c$ldap_searches[message_id]?$base_objects )
      c$ldap_searches[message_id]$base_objects = vector();
    c$ldap_searches[message_id]$base_objects += base_object;
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

  if ( ! c$ldap_messages[message_id]?$opcodes )
    c$ldap_messages[message_id]$opcodes = set();

  if (authType == LDAP::BindAuthType_BIND_AUTH_SIMPLE) {
    add c$ldap_messages[message_id]$opcodes[BIND_SIMPLE];
  } else if (authType == LDAP::BindAuthType_BIND_AUTH_SASL) {
    add c$ldap_messages[message_id]$opcodes[BIND_SASL];
  }

}

#############################################################################
event connection_state_remove(c: connection) {

  # log any "pending" unlogged LDAP messages/searches

  if ( c?$ldap_messages && (|c$ldap_messages| > 0) ) {
    for ( [mid], m in c$ldap_messages ) {
      if (mid > 0) {

        if ((BIND_SIMPLE in m$opcodes) || (BIND_SASL in m$opcodes)) {
          # don't have both "bind" and "bind <method>" in the operations list
          delete m$opcodes[PROTOCOL_OPCODES[LDAP::ProtocolOpcode_BIND_REQUEST]];
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
