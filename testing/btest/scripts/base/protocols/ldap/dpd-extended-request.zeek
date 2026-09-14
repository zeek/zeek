# Copyright (c) 2026 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: zeek -C -r ${TRACES}/ldap/ldap-extended-request-dpd.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m ldap.log
# @TEST-EXEC: btest-diff-cut -m conn.log
# @TEST-EXEC: ! test -f analyzer.log
#
# @TEST-DOC: Verify LDAP DPD recognizes a connection starting with ExtendedRequest.

@load base/protocols/ldap
