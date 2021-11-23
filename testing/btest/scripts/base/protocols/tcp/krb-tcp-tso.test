# This test checks that packets get forwarded to a protocol analyzer,
# even when TCP segment offloading is enabled, and the IP length field is
# not correctly filled out. This requires -C to be passed.
#
# @TEST-EXEC: zeek -C -r $TRACES/krb/kerberos_tso.pcap
# @TEST-EXEC: btest-diff kerberos.log
