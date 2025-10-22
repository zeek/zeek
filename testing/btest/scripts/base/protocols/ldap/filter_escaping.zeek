# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: zeek -C -r ${TRACES}/ldap/ldap_escaping_test.pcapng %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff ldap_search.log
#
# @TEST-DOC: Test escaping of specific characters in LDAP filter strings.
