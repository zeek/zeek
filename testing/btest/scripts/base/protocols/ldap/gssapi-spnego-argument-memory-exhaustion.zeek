# @TEST-DOC: Tests validation of GSSAPI NegTokenResp indexes
#
# @TEST-EXEC: zeek -b -r $TRACES/ldap/gssapi-spnego-argument-memory-exhaustion.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m ldap.log
# @TEST-EXEC: btest-diff-cut -m analyzer_debug.log

@load base/protocols/ldap
@load frameworks/analyzer/debug-logging
