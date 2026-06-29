# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: zeek -C -r ${TRACES}/ldap/ctu-60387-63723-ldap.pcap frameworks/analyzer/debug-logging %INPUT
#
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m analyzer_debug.log
# @TEST-EXEC: btest-diff-cut -m ntlm.log
#
# @TEST-DOC: Test LDAP where SASL mechanism is GSS-SPNEGO but payload is plain NTLMSSP. Ensures GSSAPI analyzer does not throw exceptions and NTLM parses it.
