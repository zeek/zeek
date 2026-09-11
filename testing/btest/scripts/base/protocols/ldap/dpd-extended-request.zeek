# Copyright (c) 2026 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: zeek -C -r ${TRACES}/ldap/ldap-extended-request-dpd.pcap %INPUT
# @TEST-EXEC: test -s ldap.log
# @TEST-EXEC: grep -q extended ldap.log
# @TEST-EXEC: ! test -f analyzer.log
#
# @TEST-DOC: Verify LDAP DPD recognizes a connection starting with ExtendedRequest.

@load base/protocols/ldap

