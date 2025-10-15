=======
ssl.log
=======

In the section discussing the :file:`http.log`, we noted that most HTTP traffic
is now encrypted and transmitted as HTTPS. Zeek does not create a
:file:`https.log`, because Zeek (or other network inspection tools, for that
matter) does not natively recognize HTTP when it is encrypted as HTTPS.

HTTPS is most often encrypted using Transport Layer Security (TLS), which
presents many variants in live traffic. Zeek parses TLS traffic and records its
findings in the :file:`ssl.log`. SSL refers to Secure Sockets Layer, an
obsolete predecessor to TLS.

TLS is not restricted to encrypting HTTPS, however. Many other protocols use
TLS to encrypt their contents, including Simple Mail Transfer Protocol (SMTP).

Remember that to see the meaning of each field in the :file:`ssl.log`, check
:zeek:see:`SSL::Info`.

Reviewing TLS Versions Seen on the Network
==========================================

To get an idea of the sorts of TLS traffic running in my network, I ran the
following command to search hundreds of days of Zeek :file:`ssl.log` entries:

.. code-block:: console

  $ for i in `find . -name ssl*.log.gz`; do zcat $i; done | jq '[."version"]' | grep -v "\]" | grep -v "\[" | sort -n | uniq -c | sort -rn

::

  11279341   "TLSv12"
  2877117   "TLSv13"
   303084   "unknown-64282"
   198154   null
    23181   "TLSv10"
     5756   "TLSv11"
      348   "DTLSv12"
       78   "DTLSv10"

TLS 1.0 and 1.1 are obsolete. TLS 1.2 and 1.3 are common, with 1.3 gaining
ground on 1.2 DTLS is a variant used to encrypt UDP traffic. ``unknown-64282``
is apparently a Facebook-created variant of TLS 1.3. Almost 20,000 connections
advertised no TLS version, but were recognized by Zeek as some form of TLS.

To try to see what protocols the TLS might be encrypting, I ran the following
command to search 10 days of Zeek :file:`ssl.log` entries:

.. code-block:: console

  $ for i in `find ./2020-08-1* -name ssl*.log.gz`; do zcat $i; done | jq -c '[."version", ."next_protocol"]' | sort -n | uniq -c | sort -rn

::

   246868 ["TLSv12",null]
   144291 ["TLSv13",null]
    86708 ["TLSv12","http/1.1"]
    85082 ["TLSv12","h2"]
     8450 ["unknown-64282",null]
     1966 [null,null]
      722 ["TLSv12","apns-pack-v1:4096:4096"]
      504 ["TLSv10",null]
      234 ["TLSv10","http/1.1"]
      154 ["TLSv12","grpc-exp"]
       83 ["TLSv11",null]
       13 ["DTLSv12",null]

``HTTP/1.1`` is obviously HTTP. The ``h2`` entry refers to the newer HTTP/2
protocol. The ``apns-pack-v1:4096:4096`` entry appears to refer to Apple Push
Notification Service, which utilizes Application Layer Protocol Negotiation
(ALPN), a TLS extension. The ``grpc-exp`` entry appears to refer to another
ALPN method that uses the gRPC remote procedure call (RPC) library.

With this brief look at the types of TLS traffic one might find in a network
done, it’s time to look at a sample connection that generates a :file:`ssl.log` entry.

Preparing to Inspect the :file:`ssl.log`
========================================

To generate network traffic that uses TLS encryption, I retrieved the index
page of the https://www.taosecurity.com using :program:`curl`.

After processing the traffic with Zeek, I had several log files to analyze.
First let’s look at the :file:`conn.log`. We will focus on the Web session
itself, and not related traffic like any DNS lookups required to resolve the
hostname to an IP address.

::

  {
    "ts": 1598377391.716515,
    "uid": "CsukF91Bx9mrqdEaH9",
    "id.orig_h": "192.168.4.49",
    "id.orig_p": 56718,
    "id.resp_h": "13.32.202.10",
    "id.resp_p": 443,
    "proto": "tcp",
    "service": "ssl",
    "duration": 0.497269868850708,
    "orig_bytes": 929,
    "resp_bytes": 31113,
    "conn_state": "SF",
    "missed_bytes": 0,
    "history": "ShADadfF",
    "orig_pkts": 37,
    "orig_ip_bytes": 2861,
    "resp_pkts": 34,
    "resp_ip_bytes": 32889
  }

We have a client, ``192.168.4.49``, interacting with a server,
``13.32.202.10``, offering an encrypted service on port 443 TCP. Zeek reports
this as ``ssl``, but that is a generic term that applies to TLS as well. We can
use the connection identifier, ``CsukF91Bx9mrqdEaH9``, to find associated Zeek
logs.

Inspecting the :file:`ssl.log` When TLS 1.2 Applies
===================================================

Using the connection identifier, we find the associated :file:`ssl.log` entry
for this conversation.

::

  {
    "ts": 1598377391.921726,
    "uid": "CsukF91Bx9mrqdEaH9",
    "id.orig_h": "192.168.4.49",
    "id.orig_p": 56718,
    "id.resp_h": "13.32.202.10",
    "id.resp_p": 443,
    "version": "TLSv12",
    "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "curve": "secp256r1",
    "server_name": "www.taosecurity.com",
    "resumed": false,
    "next_protocol": "h2",
    "established": true,
    "cert_chain_fuids": [
      "F2XEvj1CahhdhtfvT4",
      "FZ7ygD3ERPfEVVohG9",
      "F7vklpOKI4yX9wmvh",
      "FAnbnR32nIIr2j9XV"
    ],
    "client_cert_chain_fuids": [],
    "subject": "CN=www.taosecurity.com",
    "issuer": "CN=Amazon,OU=Server CA 1B,O=Amazon,C=US"
  }

This is a rich log entry that tells us a lot about the connection. We see that
the server and client agree to speak TLS 1.2, with the designated cipher suite
and elliptic curve. The server name, ``www.taosecurity.com`` appears, which
matches the subject of the certificate presented by the Web server. We can see
that Amazon issued the certificate. The next protocol involved was HTTP/2, as
the ``next_protocol`` field lists ``h2``. Zeek provides file identifiers for
the four certificates that the server presented to the client. The client did
not present any certificates to the server.

We will use the certificate information when we look at the next log in our
series, the :file:`x509.log`.

Inspecting the :file:`ssl.log` When TLS 1.3 Applies
===================================================

The last section showed Zeek’s :file:`ssl.log` when visiting a server that
negotiated a TLS 1.2 connection. The following example shows how the situation
changes when the parties use TLS 1.3.

To generate the traffic, I used :program:`curl` with a switch to try TLS 1.3
encryption.

.. code-block:: console

  $ curl -v --tlsv1.3 https://www.taosecurity.com

:program:`curl` provided the following, in addition to the content of the Web
site:

::

  * Connected to www.taosecurity.com (13.32.202.2) port 443 (#0)
  * ALPN, offering h2
  * ALPN, offering http/1.1
  * successfully set certificate verify locations:
  *   CAfile: C:\ProgramData\chocolatey\lib\curl\tools\curl-7.72.0-win64-mingw\bin\curl-ca-bundle.crt
    CApath: none
  } [5 bytes data]
  * TLSv1.3 (OUT), TLS handshake, Client hello (1):
  } [512 bytes data]
  * TLSv1.3 (IN), TLS handshake, Server hello (2):
  { [122 bytes data]
  * TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
  { [19 bytes data]
  * TLSv1.3 (IN), TLS handshake, Certificate (11):
  { [4880 bytes data]
  * TLSv1.3 (IN), TLS handshake, CERT verify (15):
  { [264 bytes data]
  * TLSv1.3 (IN), TLS handshake, Finished (20):
  { [36 bytes data]
  * TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
  } [1 bytes data]
  * TLSv1.3 (OUT), TLS handshake, Finished (20):
  } [36 bytes data]
  * SSL connection using TLSv1.3 / TLS_AES_128_GCM_SHA256
  * ALPN, server accepted to use h2
  * Server certificate:
  *  subject: CN=www.taosecurity.com
  *  start date: Jun  1 00:00:00 2020 GMT
  *  expire date: Jul  1 12:00:00 2021 GMT
  *  subjectAltName: host "www.taosecurity.com" matched cert's "www.taosecurity.com"
  *  issuer: C=US; O=Amazon; OU=Server CA 1B; CN=Amazon
  *  SSL certificate verify ok.
  * Using HTTP2, server supports multi-use
  * Connection state changed (HTTP/2 confirmed)
  * Copying HTTP/2 data in stream buffer to connection buffer after upgrade: len=0
  } [5 bytes data]
  * Using Stream ID: 1 (easy handle 0x1f9ff0c7600)
  } [5 bytes data]
  > GET / HTTP/2
  > Host: www.taosecurity.com
  > user-agent: curl/7.72.0
  > accept: */*
  >
  { [5 bytes data]
  * Connection state changed (MAX_CONCURRENT_STREAMS == 128)!
  } [5 bytes data]
  < HTTP/2 200
  < content-type: text/html
  < content-length: 28708
  < date: Tue, 01 Sep 2020 18:07:59 GMT
  < last-modified: Tue, 01 Sep 2020 14:36:01 GMT
  < etag: "9a6a530f507d79ba54daa5872b3cad22"
  < accept-ranges: bytes
  < server: AmazonS3
  < vary: Accept-Encoding
  < x-cache: Miss from cloudfront
  < via: 1.1 c09a013ad199e52fd50ddc5543a72f45.cloudfront.net (CloudFront)
  < x-amz-cf-pop: IAD66-C1
  < x-amz-cf-id: wXc1bcKla5qIePZ29LBk1fgATzgf1jLYiRvSmnyZcb7Q1eB_ZJSbaA==
  <
  { [16032 bytes data]

Note that the certificate details are visible here, because we are looking from
the perspective of the Web client, not a passive network observation system.

Here is the :file:`conn.log`:

::

  {
    "ts": 1598983678.546522,
    "uid": "CcJfBs3hXLJn7oHVu7",
    "id.orig_h": "192.168.4.142",
    "id.orig_p": 58802,
    "id.resp_h": "13.32.202.2",
    "id.resp_p": 443,
    "proto": "tcp",
    "service": "ssl",
    "duration": 0.13053107261657715,
    "orig_bytes": 831,
    "resp_bytes": 34650,
    "conn_state": "SF",
    "missed_bytes": 0,
    "history": "ShADadFf",
    "orig_pkts": 17,
    "orig_ip_bytes": 1523,
    "resp_pkts": 30,
    "resp_ip_bytes": 35862
  }

Here is the :file:`ssl.log`:

::

  {
    "ts": 1598983678.585087,
    "uid": "CcJfBs3hXLJn7oHVu7",
    "id.orig_h": "192.168.4.142",
    "id.orig_p": 58802,
    "id.resp_h": "13.32.202.2",
    "id.resp_p": 443,
    "version": "TLSv13",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "curve": "x25519",
    "server_name": "www.taosecurity.com",
    "resumed": true,
    "established": true
  }

Note that there is no mention of certificates in the :file:`ssl.log`. TLS 1.3
hides these from passive observation systems. We are able to see the server
name, ``www.taosecurity.com``, however, as well as some information about the
encryption used. These include the TLS version, the cipher, and the elliptic
curve.

Inspecting the :file:`ssl.log` When ESNI/ECH Applies
====================================================

There is one more concern for an analyst working with the :file:`ssl.log`.

Encrypted Server Name Indication (ESNI) or Encrypted Client Hello (ECH) are
methods by which the Server Name Identification field is no longer sent as
plain text. The mechanics of this process are less important than the effects
on Zeek :file:`ssl.log` entries.

To generate traffic for this example, I used a modern version of Firefox,
configured to support ESNI, and visited a Web site,
``https://only.esni.defo.ie/``, that only accepts connections from systems
supporting ESNI.

After processing the traffic with Zeek, I had the following logs.

First, I had two :file:`conn.log` entries::

  {"ts":1598631659.652789,"uid":"Cg9oVc87cdxWf5Dla","id.orig_h":"192.168.4.142","id.orig_p":63213,"id.resp_h":"185.24.233.103","id.resp_p":443,"proto":"tcp","service":"ssl","duration":5.702061891555786,"orig_bytes":1467,"resp_bytes":3160,"conn_state":"SF","missed_bytes":0,"history":"ShADadTtFf","orig_pkts":11,"orig_ip_bytes":2347,"resp_pkts":8,"resp_ip_bytes":4645}

  {"ts":1598631659.331871,"uid":"Cixuvq2LQrbqxU4Y17","id.orig_h":"192.168.4.142","id.orig_p":63210,"id.resp_h":"185.24.233.103","id.resp_p":443,"proto":"tcp","service":"ssl","duration":6.023154020309448,"orig_bytes":2193,"resp_bytes":45269,"conn_state":"SF","missed_bytes":0,"history":"ShADadFf","orig_pkts":14,"orig_ip_bytes":2765,"resp_pkts":37,"resp_ip_bytes":46761}

Second, I had two :file:`ssl.log` entries::

  {
    "ts": 1598631659.431907,
    "uid": "Cixuvq2LQrbqxU4Y17",
    "id.orig_h": "192.168.4.142",
    "id.orig_p": 63210,
    "id.resp_h": "185.24.233.103",
    "id.resp_p": 443,
    "version": "TLSv13",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "curve": "x25519",
    "resumed": true,
    "established": true
  }
  {
    "ts": 1598631659.752715,
    "uid": "Cg9oVc87cdxWf5Dla",
    "id.orig_h": "192.168.4.142",
    "id.orig_p": 63213,
    "id.resp_h": "185.24.233.103",
    "id.resp_p": 443,
    "version": "TLSv13",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "curve": "x25519",
    "resumed": true,
    "established": true
  }

As you can see, there is no identifying information in the :file:`ssl.log`
here. There are no certificate identifier entries either, although we will talk
about that log type in the next section. As the visit to
``https://only.esni.defo.ie/`` also used DNS over HTTPs (DoH), there is no DNS
record showing the identity of the remote server, as might be revealed in a
conventional DNS request and response.

As you might expect, this situation has some network security monitoring
practitioners concerned by the loss of visibility, and the opportunity for
intruders to leverage ESNI-enabled servers and Doh-enabled clients to evade
inspection.

Leveraging JA3 and JA3S
=======================

JA3 and JA3S are mechanisms to profile the TLS implementations on clients and
servers, respectively. These are clever tools to tell analysts more about each
end of a connection. To learn more, see the following project page:

https://github.com/salesforce/ja3

When running Zeek with the JA3 and JA3S packages, the scripts will append data
to the :file:`ssl.log` as follows.

In the first example, a Web client (curl) connects to the Google Web site using
TLS 1.3. The :file:`ssl.log` shows the following entry.

.. literal-emph::

  {
    "ts": "2020-09-16T14:01:26.194646Z",
    "uid": "CH3QeG4kCxFL8eZrs1",
    "id.orig_h": "192.168.4.37",
    "id.orig_p": 58842,
    "id.resp_h": "172.217.15.100",
    "id.resp_p": 443,
    "version": "TLSv13",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "curve": "x25519",
    "server_name": "www.google.com",
    "resumed": true,
    "established": true,
    **"ja3": "3830b2a4fbcea64e74db382e467f5b3b",**
    **"ja3s": "907bf3ecef1c987c889946b737b43de8"**
  }

Zeek computes the JA3 (client) and JA3S (server) hashes as shown.

In the second example, the same Web client connects to the Corelight Web site.

.. literal-emph::

  {
    "ts": "2020-09-16T13:58:21.878466Z",
    "uid": "CtbyI4sDwTIPROUv6",
    "id.orig_h": "192.168.4.37",
    "id.orig_p": 49572,
    "id.resp_h": "99.86.230.78",
    "id.resp_p": 443,
    "version": "TLSv13",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "curve": "x25519",
    "server_name": "www.corelight.com",
    "resumed": true,
    "established": true,
    **"ja3": "3830b2a4fbcea64e74db382e467f5b3b",**
    **"ja3s": "f4febc55ea12b31ae17cfb7e614afda8"**
  }

The JA3 (client) hash has stayed the same, but the JA3S (server) hash has
changed.

In the third example, the same Web client connects to the TaoSecurity Web site.

.. literal-emph::

  {
    "ts": "2020-09-16T13:54:57.033503Z",
    "uid": "CXc63QyS40XspAmcd",
    "id.orig_h": "192.168.4.37",
    "id.orig_p": 41608,
    "id.resp_h": "99.84.222.6",
    "id.resp_p": 443,
    "version": "TLSv13",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "curve": "x25519",
    "server_name": "www.taosecurity.com",
    "resumed": true,
    "established": true,
    **"ja3": "0bae189478c11bed9d6259ae0ffc9493",**
    **"ja3s": "f4febc55ea12b31ae17cfb7e614afda8"**
  }

This is an odd result. The JA3 (client) hash has changed, but the JA3S (server)
hash has stayed the same. I can explain the server hash staying the same by
noting that both the Corelight and TaoSecurity Web sites appear to be hosted by
Amazon, meaning the Web servers providing each site are offering the same TLS
parameters.

However, I would have expected the JA3 (client) hash to have been the same as
the previous two examples. I repeated the connection and got the same JA3 and
JA3S hashes.

Conclusion
==========

This section showed that the default :file:`ssl.log` provides several details
of interest to defenders, even when inspecting encrypted traffic. As
administrators and intruders deploy newer encryption technologies, however,
defenders will find it increasingly difficult to differentiate among normal,
suspicious, and malicious traffic.
