# @TEST-EXEC: zeek -C -r $TRACES/tls/x509-generalizedtime.pcap %INPUT >>output 2>&1
# @TEST-EXEC: zeek -C -r $TRACES/tls/tls1.2.trace %INPUT >>output 2>&1
# @TEST-EXEC: btest-diff output
event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
        {
                print "----- x509_certificate ----";
                print fmt("serial: %s", cert$serial);
                print fmt("not_valid_before: %T (epoch: %s)", cert$not_valid_before, cert$not_valid_before);
                print fmt("not_valid_after : %T (epoch: %s)", cert$not_valid_after, cert$not_valid_after);
        }
