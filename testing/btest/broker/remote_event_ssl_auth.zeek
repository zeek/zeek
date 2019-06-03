# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run recv "zeek -B broker -b ../recv.zeek >recv.out"
# @TEST-EXEC: btest-bg-run send "zeek -B broker -b ../send.zeek >send.out"
#
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff send/send.out


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

@TEST-START-FILE cert.2.pem
-----BEGIN CERTIFICATE-----
MIIDOjCCAiICCQDz7oMOR7Wm7TANBgkqhkiG9w0BAQsFADBkMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCQ0ExETAPBgNVBAcMCEJlcmtlbGV5MSMwIQYDVQQKDBpBQ01F
IFNpZ25pbmcgQXV0aG9yaXR5IEluYzEQMA4GA1UEAwwHZm9vLmJhcjAgFw0xNzA0
MjEyMzI2MzNaGA80NzU1MDMxOTIzMjYzM1owWDELMAkGA1UEBhMCVVMxCzAJBgNV
BAgMAkNBMREwDwYDVQQHDAhCZXJrZWxleTEVMBMGA1UECgwMQUNNRSBTZXJ2aWNl
MRIwEAYDVQQDDAkyLmZvby5iYXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDG9fAvW9qnhjGRmLpA++RvOHaesu7NiUQvxf2F6gF2rLJV0/+DSA/PztEv
1WJaGhgJSaEqUjaHk3HY2EKlbGXEPh1mxqgPZD5plGlu4ddTwutxCxxQiFIBH+3N
MYRjJvDN7ozJoi4uRiK0QQdDWAqWJs5hMOJqeWd6MCgmVXSP6pj5/omGROktbHzD
9jJhAW9fnYFg6k+7cGN5kLmjqqnGhJkNtgom6uW9j73S9OpU/9Er2aZme6/PrujI
qYFBV81TJK2vmonWUITxfQjk9JVJYhBdHamGTxUqVBbuRcbAqdImV9yx4LoGh55u
L6xnsW4i0n1o1k+bh03NgwPz12O3AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJmN
yCdInFIeEwomE6m+Su82BWBzkztOfMG9iRE+1aGuC8EQ8kju5NNMmWQcuKetNh0s
hJVdY6LXh27O0ZUllhQ/ig9c+dYFh6AHoZU7WjiNKIyWuyl4IAOkQ4IEdsBvst+l
0rafcdJjUpqNOMWeyg6x1s+gUD5o+ZLCZGCdkCW3fZbKgF52L+vmsSRiJg2JkYZW
8BPNNsroHZw2UXnLvRqUXCMf1hnOrlx/B0a0Q46hD4NQvl+OzlKaxfR2L2USmJ8M
XZvT6+i8fWvkGv18iunm23Yu+8Zf08wTXnbqXvmMda5upAYLmwD0YKIVYC3ycihh
mkYCYI6PVeH63a2/zxw=
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

@TEST-START-FILE key.2.pem
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAxvXwL1vap4YxkZi6QPvkbzh2nrLuzYlEL8X9heoBdqyyVdP/
g0gPz87RL9ViWhoYCUmhKlI2h5Nx2NhCpWxlxD4dZsaoD2Q+aZRpbuHXU8LrcQsc
UIhSAR/tzTGEYybwze6MyaIuLkYitEEHQ1gKlibOYTDianlnejAoJlV0j+qY+f6J
hkTpLWx8w/YyYQFvX52BYOpPu3BjeZC5o6qpxoSZDbYKJurlvY+90vTqVP/RK9mm
Znuvz67oyKmBQVfNUyStr5qJ1lCE8X0I5PSVSWIQXR2phk8VKlQW7kXGwKnSJlfc
seC6Boeebi+sZ7FuItJ9aNZPm4dNzYMD89djtwIDAQABAoIBAQDDaWquGRl40GR/
C/JjQQPr+RkIZdYGKXu/MEcA8ATf+l5tzfp3hp+BCzCKOpqOxHI3LQoN9xF3t2lq
AX3z27NYO2nFN/h4pYxnRk0Hiulia1+zd6YnsrxYPnPhxXCxsd1xZYsBvzh8WoZb
ZEMt8Zr0PskUzF6VFQh9Ci9k9ym07ooo/KqP4wjXsm/JK1ueOCTpRtabrBI1icrV
iTaw1JEGqlTAQ92vg3pXqSG5yy69Krt7miZZtiOA5mJ90VrHtlNSgp31AOcVv/Ve
/LMIwJp9EzTN+4ipT7AKPeJAoeVqpFjQk+2cW44zJ7xyzw73pTs5ErxkEIhQOp4M
ak2iMg4BAoGBAOivDZSaOcTxEB3oKxYvN/jL9eU2Io9wdZwAZdYQpkgc8lkM9elW
2rbHIwifkDxQnZbl3rXM8xmjA4c5PSCUYdPnLvx6nsUJrWTG0RjakHRliSLthNEC
LpL9MR1aQblyz1D/ulWTFOCNvHU7m3XI3RVJEQWu3qQ5pCndzT56wXjnAoGBANrl
zKvR9o2SONU8SDIcMzXrO2647Z8yXn4Kz1WhWojhRQQ1V3VOLm8gBwv8bPtc7LmE
MSX5MIcxRoHu7D98d53hd+K/ZGYV2h/638qaIEgZDf2oa8QylBgvoGljoy1DH8nN
KKOgksqWK0AAEkP0+S4IFugTxHVanw8JUkV0gVSxAoGBANIRUGJrxmHt/M3zUArs
QE0G3o28DQGQ1y0rEsVrLKQINid9UvoBpt3C9PcRD2fUpCGakDFzwbnQeRv46h3i
uFtV6Q6aKYLcFMXZ1ObqU+Yx0NhOtUz4+lFL8q58UL/7Tf3jkjc13XBJpe31DYoN
+MMBvzNxR6HeRD5j96tDqi3bAoGAT57SqZS/l5MeNQGuSPvU7MHZZlbBp+xMTpBk
BgOgyLUXw4Ybf8GmRiliJsv0YCHWwUwCDIvtSN91hAGB0T3WzIiccM+pFzDPnF5G
VI1nPJJQcnl2aXD0SS/ZqzvguK/3uhFzvMDFZAbnSGo+OpW6pTGwE05NYVpLDM8Z
K8ZK3KECgYEApNoI5Mr5tmtjq4sbZrgQq6cMlfkIj9gUubOzFCryUb6NaB38Xqkp
2N3/jqdkR+5ZiKOYhsYj+Iy6U3jyqiEl9VySYTfEIfP/ky1CD0a8/EVC9HR4iG8J
im6G7/osaSBYAZctryLqVJXObTelgEy/EFwW9jW8HVph/G+ljmHOmuQ=
-----END RSA PRIVATE KEY-----
@TEST-END-FILE

@TEST-START-FILE cert.2.pem
-----BEGIN CERTIFICATE-----
MIIDOjCCAiICCQDz7oMOR7Wm7TANBgkqhkiG9w0BAQsFADBkMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCQ0ExETAPBgNVBAcMCEJlcmtlbGV5MSMwIQYDVQQKDBpBQ01F
IFNpZ25pbmcgQXV0aG9yaXR5IEluYzEQMA4GA1UEAwwHZm9vLmJhcjAgFw0xNzA0
MjEyMzI2MzNaGA80NzU1MDMxOTIzMjYzM1owWDELMAkGA1UEBhMCVVMxCzAJBgNV
BAgMAkNBMREwDwYDVQQHDAhCZXJrZWxleTEVMBMGA1UECgwMQUNNRSBTZXJ2aWNl
MRIwEAYDVQQDDAkyLmZvby5iYXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDG9fAvW9qnhjGRmLpA++RvOHaesu7NiUQvxf2F6gF2rLJV0/+DSA/PztEv
1WJaGhgJSaEqUjaHk3HY2EKlbGXEPh1mxqgPZD5plGlu4ddTwutxCxxQiFIBH+3N
MYRjJvDN7ozJoi4uRiK0QQdDWAqWJs5hMOJqeWd6MCgmVXSP6pj5/omGROktbHzD
9jJhAW9fnYFg6k+7cGN5kLmjqqnGhJkNtgom6uW9j73S9OpU/9Er2aZme6/PrujI
qYFBV81TJK2vmonWUITxfQjk9JVJYhBdHamGTxUqVBbuRcbAqdImV9yx4LoGh55u
L6xnsW4i0n1o1k+bh03NgwPz12O3AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJmN
yCdInFIeEwomE6m+Su82BWBzkztOfMG9iRE+1aGuC8EQ8kju5NNMmWQcuKetNh0s
hJVdY6LXh27O0ZUllhQ/ig9c+dYFh6AHoZU7WjiNKIyWuyl4IAOkQ4IEdsBvst+l
0rafcdJjUpqNOMWeyg6x1s+gUD5o+ZLCZGCdkCW3fZbKgF52L+vmsSRiJg2JkYZW
8BPNNsroHZw2UXnLvRqUXCMf1hnOrlx/B0a0Q46hD4NQvl+OzlKaxfR2L2USmJ8M
XZvT6+i8fWvkGv18iunm23Yu+8Zf08wTXnbqXvmMda5upAYLmwD0YKIVYC3ycihh
mkYCYI6PVeH63a2/zxw=
-----END CERTIFICATE-----
@TEST-END-FILE

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

@TEST-START-FILE send.zeek

redef exit_only_after_terminate = T;

redef Broker::ssl_cafile = "../ca.pem";
redef Broker::ssl_keyfile = "../key.1.pem";
redef Broker::ssl_certificate = "../cert.1.pem";

global event_count = 0;

global ping: event(msg: string, c: count);

event zeek_init()
    {
    Broker::subscribe("bro/event/my_topic");
    Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
    }

function send_event()
    {
    ++event_count;
    local e = Broker::make_event(ping, "my-message", event_count);
    Broker::publish("bro/event/my_topic", e);
    }

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
    {
    print fmt("sender added peer: endpoint=%s msg=%s",
    endpoint$network$address, msg);
    send_event();
    }

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
    {
    print fmt("sender lost peer: endpoint=%s msg=%s",
    endpoint$network$address, msg);
    terminate();
    }

event pong(msg: string, n: count)
    {
    print fmt("sender got pong: %s, %s", msg, n);
    send_event();
    }

@TEST-END-FILE


@TEST-START-FILE recv.zeek

redef exit_only_after_terminate = T;

redef Broker::ssl_cafile = "../ca.pem";
redef Broker::ssl_keyfile = "../key.2.pem";
redef Broker::ssl_certificate = "../cert.2.pem";

const events_to_recv = 5;

global handler: event(msg: string, c: count);
global auto_handler: event(msg: string, c: count);

global pong: event(msg: string, c: count);

event zeek_init()
        {
        Broker::subscribe("bro/event/my_topic");
        Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
        }

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
        {
        print fmt("receiver added peer: endpoint=%s msg=%s", endpoint$network$address, msg);
        }

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
        {
        print fmt("receiver lost peer: endpoint=%s msg=%s", endpoint$network$address, msg);
        }

event ping(msg: string, n: count)
        {
        print fmt("receiver got ping: %s, %s", msg, n);

        if ( n == events_to_recv )
                {
		print get_broker_stats();
                terminate();
                return;
                }

        local e = Broker::make_event(pong, msg, n);
        Broker::publish("bro/event/my_topic", e);
        }

@TEST-END-FILE
