# @TEST-DOC: Run a single node cluster (manager) with a websocket server that has TLS enabled.
#
# @TEST-REQUIRES: have-zeromq
# @TEST-REQUIRES: python3 -c 'import websockets.asyncio'
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
# @TEST-PORT: WEBSOCKET_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-simple.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC: zeek -b --parse-only manager.zeek
# @TEST-EXEC: python3 -m py_compile client.py
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run client "python3 ../client.py >out"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./manager/.stderr
# @TEST-EXEC: btest-diff ./client/out
# @TEST-EXEC: btest-diff ./client/.stderr

# @TEST-START-FILE manager.zeek
@load ./zeromq-test-bootstrap
redef exit_only_after_terminate = T;

global ping_count = 0;

global ping: event(msg: string, c: count) &is_used;
global pong: event(msg: string, c: count) &is_used;

event zeek_init()
	{
	Cluster::subscribe("/zeek/event/my_topic");

	local tls_options = Cluster::WebSocketTLSOptions(
		$enable=T,
		$cert_file="../localhost.crt",
		$key_file="../localhost.key",
	);
	Cluster::listen_websocket("127.0.0.1", to_port(getenv("WEBSOCKET_PORT")), tls_options);
	}

event ping(msg: string, n: count) &is_used
	{
	++ping_count;
	print fmt("got ping: %s, %s", msg, n);
	local e = Cluster::make_event(pong, "my-message", ping_count);
	Cluster::publish("/zeek/event/my_topic", e);
	}

event Cluster::websocket_client_added(info: Cluster::EndpointInfo)
	{
	print "Cluster::websocket_client_added";
	}

event Cluster::websocket_client_lost(info: Cluster::EndpointInfo)
	{
	print "Cluster::websocket_client_lost";
	terminate();
	}
# @TEST-END-FILE


@TEST-START-FILE client.py
import asyncio, json, os
from websockets.asyncio.client import connect

ws_port = os.environ['WEBSOCKET_PORT'].split('/')[0]
ws_url = f'wss://localhost:{ws_port}/messages/json'
topic = '/zeek/event/my_topic'

# Make the websockets library use the custom server cert.
# https://stackoverflow.com/a/55856969
os.environ["SSL_CERT_FILE"] = "../localhost.crt"

def make_ping(c):
    return {
        "type": "data-message",
        "topic": topic,
        "@data-type": "vector",
        "data": [
            {"@data-type": "count", "data": 1},  # Format
            {"@data-type": "count", "data": 1},  # Type
            {"@data-type": "vector", "data": [
                { "@data-type": "string", "data": "ping"},  # Event name
                { "@data-type": "vector", "data": [  # event args
                    {"@data-type": "string", "data": f"python-websocket-client"},
                    {"@data-type": "count", "data": c},
                ], },
            ], },
        ],
    }

async def run():
    print("Connecting...")
    async with connect(ws_url) as ws:
        print("Connected!")
        # Send subscriptions
        await ws.send(json.dumps([topic]))
        ack = json.loads(await ws.recv())
        assert "type" in ack
        assert ack["type"] == "ack"
        assert "endpoint" in ack
        assert "version" in ack

        for i in range(5):
            print("Sending ping", i)
            await ws.send(json.dumps(make_ping(i)))
            print("Receiving pong", i)
            pong = json.loads(await ws.recv())
            assert pong["@data-type"] == "vector"
            ev = pong["data"][2]["data"]
            print("topic", pong["topic"], "event name", ev[0]["data"], "args", ev[1]["data"])

def main():
	asyncio.run(run())

if __name__ == "__main__":
    main()
@TEST-END-FILE

# The cert and key were generated with OpenSSL using the following command,
# taken from https://letsencrypt.org/docs/certificates-for-localhost/
#
# The test will generate the script, but the certificate is valid
# for 10 years.
@TEST-START-FILE gen-localhost-certs.sh
#!/usr/bin/env bash
openssl req -x509 -out localhost.crt -keyout localhost.key \
    -newkey rsa:2048 -nodes -sha256 -days 3650 \
    -subj '/CN=localhost' -extensions EXT -config <( \
    printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
@TEST-END-FILE

@TEST-START-FILE localhost.crt
-----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgIUDaa7Mb5u36Iqs7Pc3vUXrPdDrekwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI1MDEyOTA5NTAyOFoXDTM1MDEy
NzA5NTAyOFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA0LhBPbIRp4uq/BX+lD5MhbrchHfGtpzUUfiuay9ysKqj
hU1JEO/CrAZiZZ/XoAEpMra7gqy1sjnZ7Iufc57Ocup3eVEjoEbU0DRYBvaZEQam
TIn6cWWUOhrZUU5JGxZ0f1xG7nFsk6i5EM6rPRPuVeQJKDInlv6w8BV9R3BBx0Xc
4oKtloJM1+6jheEVJIkbaIR9UFrG5Szq84cSj4sMayzCqUvvk1MdJ2GBNpNkDEcY
m7C3oiid9P69d+vbYczSHmFsy7tOgjvBZpUFozimWOCFywJ4LGKmcgnbJPPNtU7i
GUusRkcFTDQrBk8z9rmIPNiDa4QmhOmBTKQRV1zDhQIDAQABo1kwVzAUBgNVHREE
DTALgglsb2NhbGhvc3QwCwYDVR0PBAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMB
MB0GA1UdDgQWBBSJe4C37n2nAbgG0BRCqvqwAt/t9TANBgkqhkiG9w0BAQsFAAOC
AQEAEKzi60bWiKfqNyrxWiVTBrU02zPllXyN48iNk27xuqiDH6vdquJx17pSzbht
uKE4zo0OEIAqnyRoGu0eWhS7FEW1rX9Ud9XD5xTksHmFfaNG9Sr/SWaGAkfKKJ9L
vEux5SHYEAmaBL2ChArma7wfPoUMizHaSJkAjxg1/tKTC6tGdHR1LZbonjyZ30g5
8+6K0G+UKgxZ3t36Y3jSMwSx/relifi6X6Oij/mv4CEIE/at3qlzgbELaLyM6CEy
Yoav4gdXgaDA/zQVVCN8YHFkH643DXvUbVesNq7NNoxM7UcATjkL7LY8mups+Ub8
m/l5lo12zgz0DuZJc7pkbCwKlQ==
-----END CERTIFICATE-----
@TEST-END-FILE

@TEST-START-FILE localhost.key
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDQuEE9shGni6r8
Ff6UPkyFutyEd8a2nNRR+K5rL3KwqqOFTUkQ78KsBmJln9egASkytruCrLWyOdns
i59zns5y6nd5USOgRtTQNFgG9pkRBqZMifpxZZQ6GtlRTkkbFnR/XEbucWyTqLkQ
zqs9E+5V5AkoMieW/rDwFX1HcEHHRdzigq2WgkzX7qOF4RUkiRtohH1QWsblLOrz
hxKPiwxrLMKpS++TUx0nYYE2k2QMRxibsLeiKJ30/r1369thzNIeYWzLu06CO8Fm
lQWjOKZY4IXLAngsYqZyCdsk8821TuIZS6xGRwVMNCsGTzP2uYg82INrhCaE6YFM
pBFXXMOFAgMBAAECggEAHsU3Ow78OtDkq4bbkgPQOLvoZDAbT9M1mwMYRa2IUULK
2i1favuJ3d4QFg7XVVuudO9LHBP1snmEZvLblkpQgdEOvYgoginHGI3K93XV8ZRj
InAKB7szu9A2/x1VOkTYdmlGfMMkgG1UoUVyqc29KpT0g6RHQWO5dp+YaVaDoAqo
u48jDqM7rodOXK2eze9sQGSZ8x+oluLK74uIa40Irly8rjQ+NmGZbaNAwL8sTLDW
Z3aTE0XjmHMm5XmhbB2msVdv7Dcx+dH5urk43hd18y+dXdNEK8q6sByz4mt2p7Y/
sdcKQh0jf+zlZHb1z6PvfRBGY2ioN2ax3F0YrhzJYQKBgQDtwQrxZKoj8LS7GA3i
GC4VJ6W2F18wq3O7efJ+YTdEevRW/0j6XAwOVvt1ZTk3gf+rxRi5339fmuH+Db9X
y4YqWg7M1lCvRXNNZIeN9aBw7LMAGAHBgfZWIN+mDXeq4YzfcyDp4TziksoTcVLQ
BsFLKSFXFkW4DdfgX84HTkgiZQKBgQDgvMx5QFY1CBT0iBVO12Ixfla5Zhpc+Pnw
usFdcbOoehG4v/WGyG+AtxA8AE43YXbse4bXLeYg9x9Xf/CYcj7sazgWpq+5yvny
YhbpNnjXuKu1jZLGLX75aC+2Sm9AEVgiRR5MAWPV7Fl9jL/dnK97rlcvajiXpudO
o7iKhf96oQKBgQDPO8hyCDBVC2Y8/gZ74F+qiNhkE5MhNRC3hN/dUJd/1TxM6E+Q
CdNoXGDqPsTUoTddXXrj6O95QeNiMlFqEThsifsEiHnjjEGoX8vX7RVf2LFdj49Y
QBOblyPZ9Tstc1P7ILq7oVwUkaYZtFlegcTR4pPw+LTkbQyRwnAu5gjyEQKBgQCz
vItT1e6cTzBjOYrBGWUA7GfzswMWpFFRBCutzke/UJFnzq5Q83Cp4r7rHdtwU1TH
YSvAYIcSilHYqwwDACvu7PlYtEsKLpmkDmsAbX5MGPfLJcTjFnPciETQZ8t90+FG
1zyZ0OrFplcUIEM6vBtksVQtKajFMMkBjdMDhpOCwQKBgCa5DSynudKm4g7f8oi8
UgOkPgvsMuN77U9i1BK7UcbudQw0vBzWwHWfNsBR/Smb35oR6Lkd6BYxZz4+1QKD
JwxYX7w34iRxZ8op+dSduLjezlGDWbFPAwSXfgO9KQOWGqbMqbvCmoLtkxhGxDZG
JZORLHHnMHGvgmoYeBp5wKC7
-----END PRIVATE KEY-----
@TEST-END-FILE
