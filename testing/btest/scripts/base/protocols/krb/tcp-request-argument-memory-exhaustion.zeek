# @TEST-DOC: Tests analyzer violations for invalid AS-REQ sessions.
#
# @TEST-EXEC: zeek -b -r $TRACES/krb/krb-tcp-request-argument-memory-exhaustion.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m kerberos.log
# @TEST-EXEC: btest-diff-cut -m analyzer_debug.log

@load base/protocols/krb
@load frameworks/analyzer/debug-logging
