# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run sender   bro -C -r $TRACES/web.trace --pseudo-realtime ../sender.bro
# @TEST-EXEC: btest-bg-run receiver bro ../receiver.bro
# @TEST-EXEC: btest-bg-wait 20
# 
# @TEST-EXEC: btest-diff sender/http.log
# @TEST-EXEC: btest-diff receiver/http.log
# 
# @TEST-EXEC: cat sender/http.log   | $SCRIPTS/diff-remove-timestamps >sender.http.log
# @TEST-EXEC: cat receiver/http.log | $SCRIPTS/diff-remove-timestamps >receiver.http.log
# @TEST-EXEC: cmp sender.http.log receiver.http.log
# 
# @TEST-EXEC: bro -x sender/events.bst | sed 's/^event \[[-0-9.]*\] //g' | grep '^http_' | grep -v http_stats | sed 's/(.*$//g' | $SCRIPTS/diff-remove-timestamps >events.snd.log
# @TEST-EXEC: bro -x receiver/events.bst | sed 's/^event \[[-0-9.]*\] //g' | grep '^http_' | grep -v http_stats | sed 's/(.*$//g' | $SCRIPTS/diff-remove-timestamps  >events.rec.log
# @TEST-EXEC: btest-diff events.rec.log
# @TEST-EXEC: btest-diff events.snd.log
# @TEST-EXEC: cmp events.rec.log events.snd.log
# 
# We don't compare the transmitted event paramerters anymore. With the dynamic
# state in there since 1.6, they don't match reliably.

@TEST-START-FILE sender.bro

@load frameworks/communication/listen
redef Communication::listen_ssl=T;

event bro_init()
    {
    capture_events("events.bst");
    }

redef peer_description = "events-send";

# Make sure the HTTP connection really gets out.
# (We still miss one final connection event because we shutdown before
# it gets propagated but that's ok.)
redef tcp_close_delay = 0secs;

redef ssl_ca_certificate = "../ca_cert.pem";
redef ssl_private_key = "../bro.pem";
redef ssl_passphrase = "my-password";

# Make sure the HTTP connection really gets out.
# (We still miss one final connection event because we shutdown before
# it gets propagated but that's ok.)
redef tcp_close_delay = 0secs;

# File-analysis fields in http.log won't get set on receiver side correctly,
# one problem is with the way serialization may send a unique ID in place
# of a full value and expect the remote side to associate that unique ID with
# a value it received at an earlier time.  So sometimes modifications the sender# makes to the value aren't seen on the receiver.
function myfh(c: connection, is_orig: bool): string
	{
	return "";
	}

event bro_init() 
	{
	# Ignore all http files.
	Files::register_protocol(Analyzer::ANALYZER_HTTP,
							 [$get_file_handle = myfh]);
	}

@TEST-END-FILE

#############

@TEST-START-FILE receiver.bro

event bro_init()
    {
    capture_events("events.bst");
    }

redef peer_description = "events-rcv";

redef Communication::nodes += {
    ["foo"] = [$host = 127.0.0.1, $events = /http_.*|signature_match|file_.*/, $connect=T, $ssl=T, $retry=1sec]
};

redef ssl_ca_certificate = "../ca_cert.pem";
redef ssl_private_key = "../bro.pem";
redef ssl_passphrase = "my-password";
                                                                                                                                    
event remote_connection_closed(p: event_peer)
	{
	terminate();
	}

@TEST-END-FILE

@TEST-START-FILE bro.pem
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQD17FE8UVaO224Y8UL2bH1okCYxr5dVytTQ93uE5J9caGADzPZe
qYPuvtPt9ivhBtf2L9odK7unQU60v6RsO3bb9bQktQbEdh0FEjnso2UHe/nLreYn
VyLCEp9Sh1OFQnMhJNYuzNwVzWOqH/TYNy3ODueZTS4YBsRyEkpEfgeoaQIDAQAB
AoGAJ/S1Xi94+Mz+Hl9UmeUWmx6QlhIJbI7/9NPA5d6fZcwvjW6HuOmh3fBzTn5o
sq8B96Xesk6gtpQNzaA1fsBKlzDSpGRDVg2odN9vIT3jd0Dub2F47JHdFCqtMUIV
rCsO+fpGtavv1zJ/rzlJz7rx4cRP+/Gwd5YlH0q5cFuHhAECQQD9q328Ye4A7o2e
cLOhzuWUZszqdIY7ZTgDtk06F57VrjLVERrZjrtAwbs77m+ybw4pDKKU7H5inhQQ
03PU40ARAkEA+C6cCM6E4hRwuR+QyIqpNC4CzgPaKlF+VONZLYYvHEwFvx2/EPtX
zOZdE4HdJwnXBYx7+AGFeq8uHhrN2Tq62QJBAMory2JAinejqKsGF6R2SPMlm1ug
0vqziRksShBqkuSqmUjHASczYnoR7S+usMb9S8PblhgrA++FHWjrnf2lwIECQQCj
+/AfpY2J8GWW/HNm/q/UiX5S75qskZI+tsXK3bmtIdI+OIJxzxFxktj3NbyRud+4
i92xvhebO7rmK2HOYg7pAkEA2wrwY1E237twoYXuUInv9F9kShKLQs19nup/dfmF
xfoVqYjJwidzPfgngowJZij7SoTaIBKv/fKp5Tq6xW3AEg==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIICZDCCAc2gAwIBAgIJAKoxR9yFGsk8MA0GCSqGSIb3DQEBBQUAMCsxKTAnBgNV
BAMTIEJybyBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MCAXDTExMDYxNTIx
MjgxNVoYDzIxMTEwNTIyMjEyODE1WjArMSkwJwYDVQQDEyBCcm8gUm9vdCBDZXJ0
aWZpY2F0aW9uIEF1dGhvcml0eTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA
9exRPFFWjttuGPFC9mx9aJAmMa+XVcrU0Pd7hOSfXGhgA8z2XqmD7r7T7fYr4QbX
9i/aHSu7p0FOtL+kbDt22/W0JLUGxHYdBRI57KNlB3v5y63mJ1ciwhKfUodThUJz
ISTWLszcFc1jqh/02Dctzg7nmU0uGAbEchJKRH4HqGkCAwEAAaOBjTCBijAdBgNV
HQ4EFgQU2vIsKYuGhHP8c7GeJLfWAjbKCFgwWwYDVR0jBFQwUoAU2vIsKYuGhHP8
c7GeJLfWAjbKCFihL6QtMCsxKTAnBgNVBAMTIEJybyBSb290IENlcnRpZmljYXRp
b24gQXV0aG9yaXR5ggkAqjFH3IUayTwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0B
AQUFAAOBgQAF2oceL61dA7WxA9lxcxsA/Fccr7+J6sO+pLXoZtx5tpknEuIUebkm
UfMGAiyYIenHi8u0Sia8KrIfuCDc2dG3DYmfX7/faCEbtSx8KtNQFIs3aXr1zhsw
3sX9fLS0gp/qHoPMuhbhlvTlMFSE/Mih3KDsZEGcifzI6ooLF0YP5A==
-----END CERTIFICATE-----
@TEST-END-FILE

@TEST-START-FILE ca_cert.pem
-----BEGIN CERTIFICATE-----
MIICZDCCAc2gAwIBAgIJAKoxR9yFGsk8MA0GCSqGSIb3DQEBBQUAMCsxKTAnBgNV
BAMTIEJybyBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MCAXDTExMDYxNTIx
MjgxNVoYDzIxMTEwNTIyMjEyODE1WjArMSkwJwYDVQQDEyBCcm8gUm9vdCBDZXJ0
aWZpY2F0aW9uIEF1dGhvcml0eTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA
9exRPFFWjttuGPFC9mx9aJAmMa+XVcrU0Pd7hOSfXGhgA8z2XqmD7r7T7fYr4QbX
9i/aHSu7p0FOtL+kbDt22/W0JLUGxHYdBRI57KNlB3v5y63mJ1ciwhKfUodThUJz
ISTWLszcFc1jqh/02Dctzg7nmU0uGAbEchJKRH4HqGkCAwEAAaOBjTCBijAdBgNV
HQ4EFgQU2vIsKYuGhHP8c7GeJLfWAjbKCFgwWwYDVR0jBFQwUoAU2vIsKYuGhHP8
c7GeJLfWAjbKCFihL6QtMCsxKTAnBgNVBAMTIEJybyBSb290IENlcnRpZmljYXRp
b24gQXV0aG9yaXR5ggkAqjFH3IUayTwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0B
AQUFAAOBgQAF2oceL61dA7WxA9lxcxsA/Fccr7+J6sO+pLXoZtx5tpknEuIUebkm
UfMGAiyYIenHi8u0Sia8KrIfuCDc2dG3DYmfX7/faCEbtSx8KtNQFIs3aXr1zhsw
3sX9fLS0gp/qHoPMuhbhlvTlMFSE/Mih3KDsZEGcifzI6ooLF0YP5A==
-----END CERTIFICATE-----
@TEST-END-FILE

