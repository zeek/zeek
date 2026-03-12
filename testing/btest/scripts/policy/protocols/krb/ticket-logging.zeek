# This test makes sure that krb ticket hashes are logged correctly.

# @TEST-EXEC: zeek -b -r $TRACES/krb/auth.pcap %INPUT
# @TEST-EXEC: btest-diff kerberos.log

@load protocols/krb/ticket-logging
