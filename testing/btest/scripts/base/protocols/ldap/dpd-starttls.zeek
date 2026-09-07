# @TEST-DOC: Detect an LDAP StartTLS exchange without a preceding Bind on a non-standard port.
# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: zeek -b -r ${TRACES}/ldap/starttls-off-port.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m uid id.orig_h id.orig_p id.resp_h id.resp_p history service conn.log
# @TEST-EXEC: if test -f ldap.log; then btest-diff-cut -m ldap.log; else echo 'No LDAP log' >ldap.log; btest-diff ldap.log; fi
# @TEST-EXEC: test ! -f analyzer.log

@load base/protocols/conn
@load base/protocols/ldap
@load base/protocols/ssl
