# @TEST-DOC: The ModifyRequest didn't consume all bytes as given via the outer &size. The PCAP in this test contains such a request. Regression for #5232.

# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: zeek -C -r ${TRACES}/ldap/ldap-size-not-consumed.pcapng %INPUT >output 2>&1
# @TEST-EXEC: btest-diff-cut -m uid id.orig_h id.resp_h id.resp_p service conn.log
# @TEST-EXEC: btest-diff-cut -m ldap.log
