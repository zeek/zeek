# @TEST-DOC: Kerberos 5 GSS-API tokens received without SPNEGO (LDAP SASL "GSSAPI" mechanism, RFC 4752) are forwarded to the KRB analyzer.
#
# @TEST-EXEC: zeek -b -r $TRACES/krb/sasl-gssapi-krb5.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: test -f analyzer.log
# @TEST-EXEC: btest-diff-cut -m ldap.log

@load base/protocols/conn
@load base/protocols/krb
@load base/protocols/ldap
