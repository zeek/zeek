# @TEST-REQUIRES: grep -q "#define OPENSSL_HAVE_KDF_H" $BUILD/zeek-config.h
# @TEST-REQUIRES: ! have-spicy-ssl  # Decryption is not supported in Spicy SSL

# @TEST-EXEC: ZEEKPATH=$ZEEKPATH:$SCRIPTS zeek -B dpd -C -r $TRACES/tls/tls12-decryption.pcap %INPUT
# @TEST-EXEC: btest-diff http.log

@load protocols/ssl/decryption
@load base/protocols/http
@load secrets

# @TEST-START-NEXT:
@load protocols/ssl/decryption
@load base/protocols/http
@load secrets
@load disable-ssl-analyzer-after-max-count

# @TEST-START-FILE secrets.zeek
module SSL;

redef SSL::secrets += {
["\xb4\x0a\x24\x4b\x48\xe4\x2e\xac\x28\x71\x44\xb1\xb7\x39\x30\x57\xca\xa1\x31\xf9\x61\xa7\x8e\x38\xb0\xe7\x7c\x1e"] = "\xbd\x01\xe5\x89\xd1\x05\x19\x9e\x9a\xb5\xfc\x9b\xd7\x58\xb5\xf2\x88\xdb\x28\xfd\x80\xaa\x02\x26\x1e\x47\x65\xac\x13\x57\xd0\x07\xfd\x08\xc7\xbd\xab\x45\x45\x0e\x01\x5a\x01\xd0\x8e\x5e\x7c\xa6",
};

@TEST-END-FILE
