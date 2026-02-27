# @TEST-DOC: Ensure no analyzer violation happens for a LDAP connection with a gap.

# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: zeek -C -r ${TRACES}/ldap/gap-data-missing.pcapng %INPUT

# @TEST-EXEC: btest-diff-cut -m uid id.orig_h id.resp_h id.resp_p service conn.log
# @TEST-EXEC: btest-diff-cut -m ldap.log
# @TEST-EXEC: test ! -f analyzer.log
