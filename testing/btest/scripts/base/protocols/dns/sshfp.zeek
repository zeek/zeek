# @TEST-EXEC: zeek -b -C -r $TRACES/dns/sshfp-trunc.pcap %INPUT > output
# @TEST-EXEC: btest-diff dns.log
# @TEST-EXEC: btest-diff output
@load base/protocols/dns

event dns_SSHFP(c: connection, msg: dns_msg, ans: dns_answer, algo: count, fptype: count, fingerprint: string)
        {
        print "SSHFP", algo, fptype, bytestring_to_hexstr(fingerprint);
        }
