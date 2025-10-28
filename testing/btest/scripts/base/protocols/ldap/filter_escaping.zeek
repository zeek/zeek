# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: zeek -C -r ${TRACES}/ldap/ldap_escaping_test.pcapng %INPUT >output.1 2>&1
# @TEST-EXEC: mv ldap_search.log ldap_search.log.1
# @TEST-EXEC: zeek -C -r ${TRACES}/ldap/ldap_search_umlaut.pcap %INPUT >output.2 2>&1
# @TEST-EXEC: mv ldap_search.log ldap_search.log.2
# @TEST-EXEC: btest-diff output.1
# @TEST-EXEC: btest-diff ldap_search.log.1
# @TEST-EXEC: btest-diff output.2
# @TEST-EXEC: btest-diff ldap_search.log.2
#
# @TEST-DOC: Test escaping of specific characters in LDAP filter strings, including making
# sure utf-8 characters are handled correctly.
