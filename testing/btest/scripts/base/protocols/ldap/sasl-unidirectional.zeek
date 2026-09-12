# Copyright (c) 2026 by the Zeek Project. See LICENSE for details.

# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: zeek -C -r ${TRACES}/ldap/krb5-sign-seal-01-server-only.pcap %INPUT
# @TEST-EXEC: ! test -f analyzer.log
# @TEST-EXEC: ! test -f weird.log
#
# @TEST-DOC: Test LDAP SASL parsing when the capture starts in one direction.

