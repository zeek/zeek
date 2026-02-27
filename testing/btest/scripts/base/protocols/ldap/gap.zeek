# @TEST-DOC: Ensure we still report an LDAP service even though we encountered a gap.

# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: zeek -r ${TRACES}/ldap/gap-data-missing.pcapng %INPUT

# @TEST-EXEC: btest-diff-cut -m uid id.orig_h id.resp_h id.resp_p service history conn.log
# @TEST-EXEC: btest-diff-cut -m ldap.log
# @TEST-EXEC: test ! -f analyzer.log
