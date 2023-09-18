# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-DOC: This test case is a regression test for #23.
#
# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: zeek -C -r ${TRACES}/ldap/issue-32.pcapng %INPUT
# @TEST-EXEC: cat ldap_search.log | zeek-cut -C uid filter base_object > ldap_search.log2 && mv ldap_search.log2 ldap_search.log
# @TEST-EXEC: btest-diff ldap_search.log
#
# @TEST-DOC: Test LDAP analyzer with small trace.
