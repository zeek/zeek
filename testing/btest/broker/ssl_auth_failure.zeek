# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run recv "zeek -B broker -b ../recv.zeek >recv.out"
# @TEST-EXEC: btest-bg-run send "zeek -B broker -b ../send.zeek >send.out"
#
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff send/send.out

@TEST-START-FILE ca.pem
-----BEGIN CERTIFICATE-----
MIIDmzCCAoOgAwIBAgIJAPLZ3e3WR0LLMA0GCSqGSIb3DQEBCwUAMGQxCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJDQTERMA8GA1UEBwwIQmVya2VsZXkxIzAhBgNVBAoM
GkFDTUUgU2lnbmluZyBBdXRob3JpdHkgSW5jMRAwDgYDVQQDDAdmb28uYmFyMB4X
DTE3MDQyMTIzMjM0OFoXDTQyMDQyMTIzMjM0OFowZDELMAkGA1UEBhMCVVMxCzAJ
BgNVBAgMAkNBMREwDwYDVQQHDAhCZXJrZWxleTEjMCEGA1UECgwaQUNNRSBTaWdu
aW5nIEF1dGhvcml0eSBJbmMxEDAOBgNVBAMMB2Zvby5iYXIwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQC6ah79JvrN3LtcPzc9bX5THdzfidWncSmowotG
SZA3gcIhlsYD3P3RCaUR9g+f2Z/l0l7ciKgWetpNtN9hRBbg5/9tFzSpCb/Y0SSG
mwtHHovEqN2MWV+Od/MUcYSlL6MmPjSDc8Ls5NSniTr9OBE9J1jm72AsuzHasjPQ
D84TlWeTSs0HW3H5VxDb15xWYFnmgBo0JylDWj0+VWI+G41Xr7Ubu9699lWSFYF9
FCtdjzM5e1CGZOMvqUbUBus38BhUAdQ4fE7Dwnn8seKh+7HpJ70omIgqG87e4DBo
HbnMAkZaekk8+LBl0Hfu8c66Utw9mNoMIlFf/AMlJyLDIpNxAgMBAAGjUDBOMB0G
A1UdDgQWBBRc6Cbyshtny6jFWZtd/cEUUfMQ3DAfBgNVHSMEGDAWgBRc6Cbyshtn
y6jFWZtd/cEUUfMQ3DAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCY
numHau9XYH5h4R2CoMdnKPMGk6V7UZZdbidLLcE4roQrYhnBdyhT69b/ySJK2Ee4
mt8T+E0wcg3k8Pr3aJEJA8eYYaJTqZvvv+TwuMBPjmE2rYSIpgMZv2tRD3XWMaQu
duLbwkclfejQHDD26xNXsxuU+WNB5kuvtNAg0oKFyFdNKElLQEcjyYzfxmCF4YX5
WmElijr1Tzuzd59rWPqC/tVIsh42vQ+P6g8Y1PDmo8eTUFveZ+wcr/eEPW6IOMrg
OW7tATcrgzNuXZ1umiuGgAPuIVqPfr9ssZHBqi9UOK9L/8MQrnOxecNUpPohcTFR
vq+Zqu15QV9T4BVWKHv0
-----END CERTIFICATE-----
@TEST-END-FILE


@TEST-START-FILE cert.1.pem
-----BEGIN CERTIFICATE-----
MIIDOjCCAiICCQDz7oMOR7Wm7jANBgkqhkiG9w0BAQsFADBkMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCQ0ExETAPBgNVBAcMCEJlcmtlbGV5MSMwIQYDVQQKDBpBQ01F
IFNpZ25pbmcgQXV0aG9yaXR5IEluYzEQMA4GA1UEAwwHZm9vLmJhcjAgFw0xNzA0
MjEyMzI2MzhaGA80NzU1MDMxOTIzMjYzOFowWDELMAkGA1UEBhMCVVMxCzAJBgNV
BAgMAkNBMREwDwYDVQQHDAhCZXJrZWxleTEVMBMGA1UECgwMQUNNRSBTZXJ2aWNl
MRIwEAYDVQQDDAkxLmZvby5iYXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDHobccAQQqbZANdOdx852W/nUzGcwpurOi8zbh9yCxMwnFMogW9AsqKEnd
sypV6Ah/cIz45PAgCdEg+1pc2DG7+E0+QlV4ChNwCDuk+FSWB6pqMTCdZcLeIwlA
GPp6Ow9v40dW7IFpDetFKXEo6kqEzR5P58Q0a6KpCtpsSMqhk57Py83wB9gPA1vp
s77kN7D5CI3oay86TA5j5nfFMT1X/77Hs24csW6CLnW/OD4f1RK79UgPd/kpPKQ1
jNq+hsR7NZTcfrAF1hcfScxnKaznO7WopSt1k75NqLdnSN1GIci2GpiXYKtXZ9l5
TErv2Oucpw/u+a/wjKlXjrgLL9lfAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAKuW
yKA2uuiNc9MKU+yVbNaP8kPaMb/wMvVaFG8FFFpCTZ0MFMLsqRpeqtj7gMK/gaJC
CQm4EyadjzfWFYDLkHzm6b7gI8digvvhjr/C2RJ5Qxr2P0iFP1buGq0CqnF20XgQ
Q+ecS43CZ77CfKfS6ZLPmAZMAwgFLImVyo5mkaTECo3+9oCnjDYBapvXLJqCJRhk
NosoTmGCV0HecWN4l38ojnXd44aSktQIND9iCLus3S6++nFnX5DHGZiv6/SnSO/6
+Op7nV0A6zKVcMOYQ0SGZPD8UQs5wDJgrR9LY29Ox5QBwu/5NqyvNSrMQaTop5vb
wkMInaq5lLxEYQDSLBc=
-----END CERTIFICATE-----
@TEST-END-FILE

@TEST-START-FILE key.1.pem
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAx6G3HAEEKm2QDXTncfOdlv51MxnMKbqzovM24fcgsTMJxTKI
FvQLKihJ3bMqVegIf3CM+OTwIAnRIPtaXNgxu/hNPkJVeAoTcAg7pPhUlgeqajEw
nWXC3iMJQBj6ejsPb+NHVuyBaQ3rRSlxKOpKhM0eT+fENGuiqQrabEjKoZOez8vN
8AfYDwNb6bO+5Dew+QiN6GsvOkwOY+Z3xTE9V/++x7NuHLFugi51vzg+H9USu/VI
D3f5KTykNYzavobEezWU3H6wBdYXH0nMZyms5zu1qKUrdZO+Tai3Z0jdRiHIthqY
l2CrV2fZeUxK79jrnKcP7vmv8IypV464Cy/ZXwIDAQABAoIBAC0Y7jmoTR2clJ9F
modWhnI215kMqd9/atdT5EEVx8/f/MQMj0vII8GJSm6H6/duLIVFksMjTM+gCBtQ
TPCOcmXJSQHYkGBGvm9fnMG+y7T81FWa+SWFeIkgFxXgzqzQLMOU72fGk9F8sHp2
Szb3/o+TmtZoQB2rdxqC9ibiJsxrG5IBVKkzlSPv3POkPXwSb1HcETqrTwefuioj
WMuMrqtm5Y3HddJ5l4JEF5VA3KrsfXWl3JLHH0UViemVahiNjXQAVTKAXIL1PHAV
J2MCEvlpA7sIgXREbmvPvZUTkt3pIqhVjZVJ7tHiSnSecqNTbuxcocnhKhZrHNtC
v2zYKHkCgYEA6cAIhz0qOGDycZ1lf9RSWw0RO1hO8frATMQNVoFVuJJCVL22u96u
0FvJ0JGyYbjthULnlOKyRe7DUL5HRLVS4D7vvKCrgwDmsJp1VFxMdASUdaBfq6aX
oKLUW4q7kC2lQcmK/PVRYwp2GQSx8bodWe+DtXUY/GcN03znY8mhSB0CgYEA2qJK
1GSZsm6kFbDek3BiMMHfO+X819owB2FmXiH+GQckyIZu9xA3HWrkOWTqwglEvzfO
qzFF96E9iEEtseAxhcM8gPvfFuXiUj9t2nH/7SzMnVGikhtYi0p6jrgHmscc4NBx
AOUA15kYEFOGqpZfl2uuKqgHidrHdGkJzzSUBqsCgYAVCjb6TVQejQNlnKBFOExN
a8iwScuZVlO21TLKJYwct/WGgSkQkgO0N37b6jFfQHEIvLPxn9IiH1KvUuFBWvzh
uGiF1wR5HzykitKizEgJbVwbllrmLXGagO2Sa9NkL+efG1AKYt53hrqIl/aYZoM7
1CZL0AV2uqPw9F4zijOdNQKBgH1WmvWGMsKjQTgaLI9z1ybCjjqlj70jHXOtt+Tx
Md2hRcobn5PN3PrlY68vlpHkhF/nG3jzB3x+GGt7ijm2IE3h7la3jl5vLb8fE9gu
kJykmSz7Nurx+GHqMbaN8/Ycfga4GIB9yGzRHIWHjOVQzb5eAfv8Vk4GeV/YM8Jx
Dwd/AoGAILn8pVC9dIFac2BDOFU5y9ZvMmZAvwRxh9vEWewNvkzg27vdYc+rCHNm
I7H0S/RqfqVeo0ApE5PQ8Sll6RvxN/mbSQo9YeCDGQ1r1rNe4Vs12GAYXAbE4ipf
BTdqMbieumB/zL97iK5baHUFEJ4VRtLQhh/SOXgew/BF8ccpilI=
-----END RSA PRIVATE KEY-----
@TEST-END-FILE

@TEST-START-FILE send.zeek

redef exit_only_after_terminate = T;

redef Broker::ssl_cafile = "../ca.pem";
redef Broker::ssl_keyfile = "../key.1.pem";
redef Broker::ssl_certificate = "../cert.1.pem";

global event_count = 0;

global ping: event(msg: string, c: count);

event do_terminate()
	{
	terminate();
	}

event zeek_init()
    {
    Broker::subscribe("bro/event/my_topic");
    Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
    schedule 5secs { do_terminate()   };
    }

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
    {
    print fmt("sender added peer: endpoint=%s msg=%s", endpoint$network$address, msg);
    }

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
    {
    print fmt("sender lost peer: endpoint=%s msg=%s", endpoint$network$address, msg);
    terminate();
    }

event Broker::error(code: Broker::ErrorCode, msg: string)
    {
    print fmt("sender error: code=%s msg=%s", code, gsub(msg, /127.0.0.1:[0-9]+/, "<endpoint addr:port>"));
    terminate();
    }

@TEST-END-FILE


@TEST-START-FILE recv.zeek

redef exit_only_after_terminate = T;

# No cert here.
# 
# redef Broker::ssl_cafile = "../ca.pem";
# redef Broker::ssl_keyfile = "../key.2.pem";
# redef Broker::ssl_certificate = "../cert.2.pem";

event do_terminate()
	{
	terminate();
	}

event zeek_init()
        {
        Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
        schedule 10secs { do_terminate()   };
        }

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
        {
        print fmt("receiver added peer: endpoint=%s msg=%s", endpoint$network$address, msg);
        }

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
        {
        print fmt("receiver lost peer: endpoint=%s msg=%s", endpoint$network$address, msg);
        }

@TEST-END-FILE
