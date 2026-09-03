# @TEST-DOC: Verify that a second originator LDAP message received before
# @TEST-DOC: its SASL BindResponse raises a weird instead of an analyzer violation.
# The pcap is a rewrite of the "krb5-sign-seal-01.pcap" with only client direction
#
# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: zeek -b -r $TRACES/ldap/unidir-sasl-weird.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m uid id.orig_h id.orig_p id.resp_h id.resp_p history service conn.log
# @TEST-EXEC: btest-diff-cut -m uid name addl source weird.log
# @TEST-EXEC: test ! -f analyzer.log



@load base/frameworks/analyzer
@load base/frameworks/notice/weird
@load base/protocols/conn
@load base/protocols/ldap
