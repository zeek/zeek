#
# @TEST-EXEC: btest-bg-run sender   bro -C -r $TRACES/web.trace --pseudo-realtime ../sender.bro
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run receiver bro ../receiver.bro
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-wait -k 5
#
# @TEST-EXEC: btest-diff sender/conn.log
# @TEST-EXEC: btest-diff sender/http.log
# @TEST-EXEC: btest-diff receiver/conn.log
# @TEST-EXEC: btest-diff receiver/http.log
# @TEST-EXEC: cat receiver/http.log | sed 's/^\([^ ]* \)\{2\}//' >http.rec.log
# @TEST-EXEC: cat sender/http.log | sed 's/^\([^ ]* \)\{2\}//' >http.snd.log
# @TEST-EXEC: cmp http.rec.log http.snd.log
#
# @TEST-EXEC: bro -x receiver/events.bst | sed 's/127.0.0.1:[0-9]*//g' | grep -v Event.*remote_ >events
# @TEST-EXEC: btest-diff events

@TEST-START-FILE sender.bro

@load tcp
@load http-request
@load http-reply
@load http-header
@load http-body
@load http-abstract
@load listen-ssl
	
@load capture-events	
	
redef peer_description = "events-send";

# Make sure the HTTP connection really gets out.
# (We still miss one final connection event because we shutdown before
# it gets propagated but that's ok.)
redef tcp_close_delay = 0secs;

redef ssl_ca_certificate = "../ca_cert.pem";
redef ssl_private_key = "../bro.pem";
redef ssl_passphrase = "my-password";

@TEST-END-FILE

#############

@TEST-START-FILE receiver.bro

@load tcp
@load http-request
@load http-reply
@load http-header
@load http-body
@load http-abstract
	
@load capture-events	
@load remote
	
redef peer_description = "events-rcv";
	
redef Remote::destinations += {
    ["foo"] = [$host = 127.0.0.1, $events = /.*/, $connect=T, $ssl=T]
};

redef ssl_ca_certificate = "../ca_cert.pem";
redef ssl_private_key = "../bro.pem";
redef ssl_passphrase = "my-password";

@TEST-END-FILE

######

@TEST-START-FILE bro.pem
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDzkuad+VHAhymnpRqkcBTU6Z3OsgUNLnsqpaxPO1LdTuxiDY9N
GuQJkFDMB/Dxu7slNepseRNu4yDDWVjcdL1TsPdSnNlnbFO3GBt0jQbYjEGLKhkt
4dUFwjBAUfEVlklYtSWuzNAz+yVUIIyDOdpCXjj4DcuBSNh4ixA+fqmQ0QIDAQAB
AoGAJWdZosi2lSosa2IfRUEw8cEuSp9rxypsH5BxdXlWsEV+Z1BNwTlv60gOIEbX
6Uc65evxo9az9UNLtLPzwWbr67F90wyPXTpG7oE2eaKqbaOFuZ4/0rc8pASSZHcO
bIVQOJbUMF+Zc3YnsNx6Ca682zQMRJrgh0745AutRkSARAECQQD9VmTAvzCqwDKG
ylWmpTTTzN+ecqDMcZh9JmUZ8W/f3m4/i2wtwfrBTNn8ovATtCs5EWVG493tgXNM
Ezgkmf65AkEA9iI89a6Ep2w5EPyYxBcm0ztbRC+vF3CSRoDgRPLwgS8kEsjhqPsE
U5wQNyvCIyIssWC9VGiZmgMaSyom3cLW2QJAHR6KFDGluWrAJAgr0izZJqM87OyG
GRnRikkYg+PhlRzvFTTEaXoLhZ58y/I6oDksYrHiL0TP5JXll8/5uxNMWQJBAJ2M
oPSqNyNr9MNYzPiH0URYtDzbQPqCBj+28tdvol8uq6qSh0/BDa3vMbn++o++qlkI
EWjcY6Xf4o7GdoZw11ECQQCyfgT2EY5HhzieGpA3MzrhATVnJlIuj8cvxFKjBriv
OCc4cxVTrCW9FPxDOuLLgh7kxalvnkuKjjCmDeTGz5Fc
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIICPTCCASWgAwIBAgIBATANBgkqhkiG9w0BAQUFADArMSkwJwYDVQQDEyBCcm8g
Um9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xMTAyMDgwNDIxMjhaFw0x
MzAyMDcwNDIxMjhaMA4xDDAKBgNVBAMTA0JybzCBnzANBgkqhkiG9w0BAQEFAAOB
jQAwgYkCgYEA85LmnflRwIcpp6UapHAU1OmdzrIFDS57KqWsTztS3U7sYg2PTRrk
CZBQzAfw8bu7JTXqbHkTbuMgw1lY3HS9U7D3UpzZZ2xTtxgbdI0G2IxBiyoZLeHV
BcIwQFHxFZZJWLUlrszQM/slVCCMgznaQl44+A3LgUjYeIsQPn6pkNECAwEAAaMN
MAswCQYDVR0TBAIwADANBgkqhkiG9w0BAQUFAAOCAQEAnG+PiWgxp7cOBkgKgnxz
JFK7J9f9fXn9vCOkzq//AitwP0A+SrBmccMtqOjjSLu7RCbmBQ9pbMwYPB4/py5f
d8SfO1ngI8cY5uXCFUylNCWJ5P+uHBNwure7hRrQwswL7+8Elour8CnVfr2Ve/qO
h2JL1fmoFcQ8KCKrNe01DsMCRq5jZ5AZI84ASiqNmzm4PwbSWiYLqZU+cemzW0xt
tYMDlN4loJTQJX7o/6izOGWY0IEggoibI80T4dIGnnZqnhpMbASTtSyN6fTNMIWQ
UQXfNM59GN1Q54UZ0HgXAgxb9jncF95rqPt9yHOUv5OUzLCdRsUWn4cEg9/rsHiu
ZA==
-----END CERTIFICATE-----
@TEST-END-FILE

@TEST-START-FILE ca_cert.pem
-----BEGIN CERTIFICATE-----
MIIC6TCCAdGgAwIBAgIJAKb0Por6917kMA0GCSqGSIb3DQEBBQUAMCsxKTAnBgNV
BAMTIEJybyBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTExMDIwODA0
MTMyM1oXDTExMDMxMDA0MTMyM1owKzEpMCcGA1UEAxMgQnJvIFJvb3QgQ2VydGlm
aWNhdGlvbiBBdXRob3JpdHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDfGHPVBuKZa3Dp/V/ntkaNvHrgK/XH02mn5mLnt7eaeCEQKClL1bvQ/iGUrMEi
CfQBe1zk6B8LnHgwkbOeAO2Kv7+K9rzn25nidAg/GU5o0gxfyqP1Sipfkr+/UrCH
3fLnjSzZIwT5ypkXZS9UNgRzK/Xk+yAJs6tB5lU+wJofPJdmiH/Ros4ZZ5P/mNf3
MhoM4Z5i3R3uEDtMCk5IT1zfXGq3FVOMA7jVYakrBccCbWhtyHdQH0i6U9wkfVEj
o6l6PBPJxhWq0ySVnGdd+i4RCiwRBfeizl2gq0UlZ7/pXjJUZZICqYNPyZdntfMy
2LUwvKA0y1RSpUrB4ZCkciZ7AgMBAAGjEDAOMAwGA1UdEwQFMAMBAf8wDQYJKoZI
hvcNAQEFBQADggEBAIDoYd7ZQpLhm7ajvhqkYdrisxQfoQoCVt+oYm5jaLvzc/1V
7sxeIatwk3kaowPcxUHHX7JfEPsf4xMGBCFp4Ce/vLXeeA2HBhBVww5sMKoAAtH6
Y2sTNt2uTE/JUxQl6N+mqmv4y+g1X7uq2N/Eg8zYbgXF6En5L3XuEBdZbSf/AgBg
d3m6m/N/dHLozZSjfwIQo0eygGEPW+kP7QFkve2L8g4l3k72mcAlCStlfcWDzKrh
qPrFFujvGMD7MNUSuNbYtGVngDuYOYeHTEggq/kUDS1srMwmv/vQjxQfS9oeU4bG
4sfSOkNotN+rwX7WQkVUq4IUOJ0q9fEPTosmsbc=
-----END CERTIFICATE-----
@TEST-END-FILE

