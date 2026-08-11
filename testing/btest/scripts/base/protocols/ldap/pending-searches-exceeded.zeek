# @TEST-DOC: Tests generation of weirds for unanswered SearchRequest.
#
# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: zeek -r ${TRACES}/ldap/pending-searches-10.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m ldap_search.log
# @TEST-EXEC: btest-diff-cut -m uid name addl source weird.log

redef LDAP::max_pending_searches = 5;
