# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: zeek -C -r ${TRACES}/ldap/simpleauth.pcap %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff-cut -Cn local_orig local_resp conn.log
# @TEST-EXEC: btest-diff ldap.log
# @TEST-EXEC: btest-diff ldap_search.log
#
# @TEST-DOC: Test LDAP analyzer with small trace.
