# @TEST-DOC: Regression test case for #3919 for invalid credentials.
#
# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: zeek -C -r ${TRACES}/ldap/ldap_invalid_credentials.pcap %INPUT
# @TEST-EXEC: btest-diff ldap.log
