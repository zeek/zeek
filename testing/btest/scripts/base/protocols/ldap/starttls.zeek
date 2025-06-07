# Copyright (c) 2024 by the Zeek Project. See LICENSE for details.

# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: zeek -r ${TRACES}/ldap/ldap-starttls.pcap %INPUT >out
# @TEST-EXEC: cat conn.log | zeek-cut -Cn local_orig local_resp > conn.log2 && mv conn.log2 conn.log
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ldap.log
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: ! test -f analyzer.log
#
# @TEST-DOC: LDAP supports StartTLS through extendedRequest 1.3.6.1.4.1.1466.20037

event LDAP::extended_request(c: connection, message_id: int, request_name: string, request_value: string) {
  print c$uid, "extended_request", fmt("%s (%s)", request_name, LDAP::EXTENDED_REQUESTS[request_name]), request_value;
}

event LDAP::extended_response(c: connection, message_id: int, result: LDAP::ResultCode, response_name: string, response_value: string) {
  print c$uid, "extended_response", result, response_name, response_value;
}

event LDAP::starttls(c: connection) {
  print c$uid, "LDAP::starttls";
}
