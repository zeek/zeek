# Copyright (c) 2024 by the Zeek Project. See LICENSE for details.

# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: zeek -C -r ${TRACES}/ldap/sasl-ntlm.pcap %INPUT
# @TEST-EXEC: cat conn.log | zeek-cut -Cn local_orig local_resp > conn.log2 && mv conn.log2 conn.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ldap.log
# @TEST-EXEC: btest-diff ldap_search.log
# @TEST-EXEC: ! test -f analyzer_failed.log
#
# @TEST-DOC: This broke after #3826 got merged
