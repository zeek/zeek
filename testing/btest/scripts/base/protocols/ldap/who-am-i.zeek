# Copyright (c) 2024 by the Zeek Project. See LICENSE for details.

# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: zeek -r ${TRACES}/ldap/ldap-who-am-i.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -Cn local_orig local_resp conn.log
# @TEST-EXEC: btest-diff ldap.log
# @TEST-EXEC: ! test -f analyzer.log
#
# @TEST-DOC: Testing OpenLDAP's ldapwhoami utility with simple authentication.

event LDAP::extended_request(c: connection, message_id: int, request_name: string, request_value: string) {
  print c$uid, "extended_request", fmt("%s (%s)", request_name, LDAP::EXTENDED_REQUESTS[request_name]), request_value;
}

event LDAP::extended_response(c: connection, message_id: int, result: LDAP::ResultCode, response_name: string, response_value: string) {
  print c$uid, "extended_response", result, response_name, response_value;
}
