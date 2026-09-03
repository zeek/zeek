# @TEST-DOC: The abandon request caused an analyzer violation previously.

# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: zeek -r ${TRACES}/ldap/ldap-abandon.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m ldap.log
# @TEST-EXEC: btest-diff-cut -m ldap_search.log
# @TEST-EXEC: ! test -f analyzer.log
