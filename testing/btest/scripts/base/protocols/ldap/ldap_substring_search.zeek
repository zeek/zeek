# Copyright (c) 2024 by the Zeek Project. See LICENSE for details.

# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: zeek -b -C -r ${TRACES}/ldap/ldap_star_single.pcap %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: cat conn.log | zeek-cut -m ts uid history service > conn.log2 && mv conn.log2 conn.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ldap_search.log
#
# @TEST-DOC: Test substring filter parsed and rendered properly when initial and final are present, but no anys.

@load base/protocols/conn
@load base/protocols/ldap
