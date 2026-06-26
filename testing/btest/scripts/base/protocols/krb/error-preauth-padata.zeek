# @TEST-DOC: Regression test for a null-pointer-deref in the KRB analyzer.
#
# @TEST-EXEC: zeek -b -r $TRACES/krb/error-preauth-padata.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m kerberos.log

@load base/protocols/krb
