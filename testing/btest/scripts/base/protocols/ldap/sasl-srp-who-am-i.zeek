# Copyright (c) 2024 by the Zeek Project. See LICENSE for details.

# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: zeek -C -r ${TRACES}/ldap/sasl-srp-who-am-i.pcap %INPUT
# @TEST-EXEC: cat conn.log | zeek-cut -Cn local_orig local_resp > conn.log2 && mv conn.log2 conn.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ldap.log
# @TEST-EXEC: ! test -f analyzer.log
#
# @TEST-DOC: SASL authentication using SRP (Secure Remote Password)
