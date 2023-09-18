# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: zeek -C -r ${TRACES}/ldap-krb5-sign-seal-01.pcap %INPUT
# @TEST-EXEC: cat conn.log | zeek-cut -Cn local_orig local_resp > conn.log2 && mv conn.log2 conn.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ldap.log
# @TEST-EXEC: btest-diff ldap_search.log
# @TEST-EXEC: ! test -f weird.log
# @TEST-EXEC: ! test -f dpd.log
#
# @TEST-DOC: Test LDAP analyzer with SASL encrypted payloads.

@load analyzer
