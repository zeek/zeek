# @TEST-SERIALIZE: comm
#
# @TEST-REQUIRES: test -e $BUILD/aux/broccoli/src/libbroccoli.so || test -e $BUILD/aux/broccoli/src/libbroccoli.dylib
#
# @TEST-EXEC: chmod 600 broccoli.conf
# @TEST-EXEC: btest-bg-run bro bro $DIST/aux/broccoli/test/broccoli-v6addrs.bro "Communication::listen_ssl=T" "ssl_ca_certificate=../ca_cert.pem" "ssl_private_key=../bro.pem"
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run broccoli BROCCOLI_CONFIG_FILE=../broccoli.conf $BUILD/aux/broccoli/test/broccoli-v6addrs
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff bro/.stdout
# @TEST-EXEC: btest-diff broccoli/.stdout

@TEST-START-FILE broccoli.conf
/broccoli/use_ssl      yes
/broccoli/ca_cert      ../ca_cert.pem
/broccoli/host_cert    ../bro.pem
/broccoli/host_key     ../bro.pem
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
