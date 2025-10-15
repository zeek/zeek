=======
dpd.log
=======

Dynamic protocol detection (DPD) is a method by which Zeek identifies protocols
on ports beyond those used as standard services. Rather than selecting which
application protocol analyzer to use based on a connection’s server port,
Zeek’s dynamic analyzer framework associates an analyzer tree with every
connection. This analyzer tree permits Zeek to perform protocol analysis
independently of port numbers.

By using a set of signatures which match typical protocol dialogues, Zeek is
able to look at payload to find the correct analyzers. When such a signature
matches, it turns on the corresponding analyzer to confirm it. Zeek can turn
off analyzers when it becomes obvious that they are parsing the wrong protocol.
This allows Zeek to use “loose” protocol signatures, and, if in doubt, try
multiple analyzers in parallel.

Zeek’s :file:`dpd.log` reports problems with the DPD mechanism. This document
will provide examples of this reporting in action.

For full details on each field in the :file:`dpd.log` file, please refer to
:zeek:see:`DPD::Info`.

One Specific Example
====================

The following is an example of traffic that generated a :file:`dpd.log` entry.

:program:`tcpdump` and :program:`tshark`
----------------------------------------

:program:`tcpdump` reports the traffic as follows::

  02:44:24.274569 IP 192.168.4.142.50540 > 184.168.176.1.443: Flags [S], seq 163388510, win 64240, options [mss 1460,nop,wscale 8,nop,nop,sackOK], length 0
  02:44:24.339007 IP 184.168.176.1.443 > 192.168.4.142.50540: Flags [S.], seq 3902980842, ack 163388511, win 14600, options [mss 1460,nop,wscale 8], length 0
  02:44:24.340486 IP 192.168.4.142.50540 > 184.168.176.1.443: Flags [.], ack 1, win 513, length 0
  02:44:24.340668 IP 192.168.4.142.50540 > 184.168.176.1.443: Flags [P.], seq 1:518, ack 1, win 513, length 517
  02:44:24.407539 IP 184.168.176.1.443 > 192.168.4.142.50540: Flags [.], ack 518, win 62, length 0
  02:44:24.410681 IP 184.168.176.1.443 > 192.168.4.142.50540: Flags [P.], seq 1:468, ack 518, win 62, length 467
  02:44:24.411048 IP 184.168.176.1.443 > 192.168.4.142.50540: Flags [F.], seq 468, ack 518, win 62, length 0
  02:44:24.412575 IP 192.168.4.142.50540 > 184.168.176.1.443: Flags [.], ack 469, win 511, length 0
  02:44:24.412857 IP 192.168.4.142.50540 > 184.168.176.1.443: Flags [P.], seq 518:525, ack 469, win 511, length 7
  02:44:24.412860 IP 192.168.4.142.50540 > 184.168.176.1.443: Flags [F.], seq 525, ack 469, win 511, length 0
  02:44:24.477936 IP 184.168.176.1.443 > 192.168.4.142.50540: Flags [.], ack 526, win 62, length 0

On the face of it, there does not appear to be anything unusual about this
traffic. It appears to be a brief session to TCP port 443.

:program:`tshark` reports the traffic as follows:

.. literal-emph::

    2 192.168.4.142 50540 184.168.176.1 443 TCP 66 50540 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM=1
    4 184.168.176.1 443 192.168.4.142 50540 TCP 62 443 → 50540 [SYN, ACK] Seq=0 Ack=1 Win=14600 Len=0 MSS=1460 WS=256
    6 192.168.4.142 50540 184.168.176.1 443 TCP 60 50540 → 443 [ACK] Seq=1 Ack=1 Win=131328 Len=0
    7 192.168.4.142 50540 184.168.176.1 443 TLSv1 571 Client Hello
    9 184.168.176.1 443 192.168.4.142 50540 TCP 60 443 → 50540 [ACK] Seq=1 Ack=518 Win=15872 Len=0
   **10 184.168.176.1 443 192.168.4.142 50540 HTTP 521 HTTP/1.1 400 Bad Request  (text/html)**
   11 184.168.176.1 443 192.168.4.142 50540 TCP 60 443 → 50540 [FIN, ACK] Seq=468 Ack=518 Win=15872 Len=0
   13 192.168.4.142 50540 184.168.176.1 443 TCP 60 50540 → 443 [ACK] Seq=518 Ack=469 Win=130816 Len=0
   14 192.168.4.142 50540 184.168.176.1 443 TCP 61 50540 → 443 [PSH, ACK] Seq=518 Ack=469 Win=130816 Len=7
   15 192.168.4.142 50540 184.168.176.1 443 TCP 60 50540 → 443 [FIN, ACK] Seq=525 Ack=469 Win=130816 Len=0
   24 184.168.176.1 443 192.168.4.142 50540 TCP 60 443 → 50540 [ACK] Seq=469 Ack=526 Win=15872 Len=0

:program:`tshark` reveals something weird is happening here. Frame 10 shows
that :program:`tshark` decoded a plain-text HTTP message from port 443 TCP.
This should not be happening. A second look shows that the TLS session did not
appear to complete, as there is no response to the TLS client hello message.

Here is frame 10 in detail. I passed :program:`tshark` the ``-x`` switch to
provide a hex and ASCII output at the end.

.. literal-emph::

  Frame 10: 521 bytes on wire (4168 bits), 521 bytes captured (4168 bits)
      Encapsulation type: Ethernet (1)
      Arrival Time: Dec 10, 2020 02:44:24.410681000 UTC
      [Time shift for this packet: 0.000000000 seconds]
      Epoch Time: 1607568264.410681000 seconds
      [Time delta from previous captured frame: 0.003142000 seconds]
      [Time delta from previous displayed frame: 0.003142000 seconds]
      [Time since reference or first frame: 0.136113000 seconds]
      Frame Number: 10
      Frame Length: 521 bytes (4168 bits)
      Capture Length: 521 bytes (4168 bits)
      [Frame is marked: False]
      [Frame is ignored: False]
      [Protocols in frame: eth:ethertype:ip:tcp:http:data-text-lines]
  Ethernet II, Src: fc:ec:da:49:e0:10, Dst: 60:f2:62:3c:9c:68
      Destination: 60:f2:62:3c:9c:68
          Address: 60:f2:62:3c:9c:68
          .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
          .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
      Source: fc:ec:da:49:e0:10
          Address: fc:ec:da:49:e0:10
          .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
          .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
      Type: IPv4 (0x0800)
  Internet Protocol Version 4, Src: 184.168.176.1, Dst: 192.168.4.142
      0100 .... = Version: 4
      .... 0101 = Header Length: 20 bytes (5)
      Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)
          0000 00.. = Differentiated Services Codepoint: Default (0)
          .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)
      Total Length: 507
      Identification: 0xcc4e (52302)
      Flags: 0x4000, Don't fragment
          0... .... .... .... = Reserved bit: Not set
          .1.. .... .... .... = Don't fragment: Set
          ..0. .... .... .... = More fragments: Not set
          ...0 0000 0000 0000 = Fragment offset: 0
      Time to live: 55
      Protocol: TCP (6)
      Header checksum: 0x47ce [validation disabled]
      [Header checksum status: Unverified]
      Source: 184.168.176.1
      Destination: 192.168.4.142
  Transmission Control Protocol, Src Port: 443, Dst Port: 50540, Seq: 1, Ack: 518, Len: 467
      Source Port: 443
      Destination Port: 50540
      [Stream index: 1]
      [TCP Segment Len: 467]
      Sequence number: 1    (relative sequence number)
      [Next sequence number: 468    (relative sequence number)]
      Acknowledgment number: 518    (relative ack number)
      0101 .... = Header Length: 20 bytes (5)
      Flags: 0x018 (PSH, ACK)
          000. .... .... = Reserved: Not set
          ...0 .... .... = Nonce: Not set
          .... 0... .... = Congestion Window Reduced (CWR): Not set
          .... .0.. .... = ECN-Echo: Not set
          .... ..0. .... = Urgent: Not set
          .... ...1 .... = Acknowledgment: Set
          .... .... 1... = Push: Set
          .... .... .0.. = Reset: Not set
          .... .... ..0. = Syn: Not set
          .... .... ...0 = Fin: Not set
          [TCP Flags: ·······AP···]
      Window size value: 62
      [Calculated window size: 15872]
      [Window size scaling factor: 256]
      Checksum: 0xde95 [unverified]
      [Checksum Status: Unverified]
      Urgent pointer: 0
      [SEQ/ACK analysis]
          [iRTT: 0.065917000 seconds]
          [Bytes in flight: 467]
          [Bytes sent since last PSH flag: 467]
      [Timestamps]
          [Time since first frame in this TCP stream: 0.136112000 seconds]
          [Time since previous frame in this TCP stream: 0.003142000 seconds]
      TCP payload (467 bytes)
  **Hypertext Transfer Protocol**
      **[Expert Info (Warning/Security): Unencrypted HTTP protocol detected over encrypted port, could indicate a dangerous misconfiguration.]**
          **[Unencrypted HTTP protocol detected over encrypted port, could indicate a dangerous misconfiguration.]**
          **[Severity level: Warning]**
          **[Group: Security]**
      **HTTP/1.1 400 Bad Request\r\n**
          [Expert Info (Chat/Sequence): HTTP/1.1 400 Bad Request\r\n]
              [HTTP/1.1 400 Bad Request\r\n]
              [Severity level: Chat]
              [Group: Sequence]
          Response Version: HTTP/1.1
          Status Code: 400
          [Status Code Description: Bad Request]
          Response Phrase: Bad Request
      Date: Thu, 10 Dec 2020 02:44:24 GMT\r\n
      Server: Apache\r\n
      Content-Length: 301\r\n
          [Content length: 301]
      Connection: close\r\n
      Content-Type: text/html; charset=iso-8859-1\r\n
      \r\n
      [HTTP response 1/1]
      File Data: 301 bytes
  Line-based text data: text/html (10 lines)
      <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n
      <html><head>\n
      <title>400 Bad Request</title>\n
      </head><body>\n
      <h1>Bad Request</h1>\n
      <p>Your browser sent a request that this server could not understand.<br />\n
      </p>\n
      <hr>\n
      <address>Apache Server at virtualhost.184.168.176.1 Port 80</address>\n
      </body></html>\n

  0000  60 f2 62 3c 9c 68 fc ec da 49 e0 10 08 00 45 00   `.b<.h...I....E.
  0010  01 fb cc 4e 40 00 37 06 47 ce b8 a8 b0 01 c0 a8   ...N@.7.G.......
  0020  04 8e 01 bb c5 6c e8 a2 c2 eb 09 bd 1e 64 50 18   .....l.......dP.
  0030  00 3e de 95 00 00 **48 54 54** 50 2f 31 2e 31 20 34   .>....**HTT**P/1.1 4
  0040  30 30 20 42 61 64 20 52 65 71 75 65 73 74 0d 0a   00 Bad Request..
  0050  44 61 74 65 3a 20 54 68 75 2c 20 31 30 20 44 65   Date: Thu, 10 De
  0060  63 20 32 30 32 30 20 30 32 3a 34 34 3a 32 34 20   c 2020 02:44:24
  0070  47 4d 54 0d 0a 53 65 72 76 65 72 3a 20 41 70 61   GMT..Server: Apa
  0080  63 68 65 0d 0a 43 6f 6e 74 65 6e 74 2d 4c 65 6e   che..Content-Len
  0090  67 74 68 3a 20 33 30 31 0d 0a 43 6f 6e 6e 65 63   gth: 301..Connec
  00a0  74 69 6f 6e 3a 20 63 6c 6f 73 65 0d 0a 43 6f 6e   tion: close..Con
  00b0  74 65 6e 74 2d 54 79 70 65 3a 20 74 65 78 74 2f   tent-Type: text/
  00c0  68 74 6d 6c 3b 20 63 68 61 72 73 65 74 3d 69 73   html; charset=is
  00d0  6f 2d 38 38 35 39 2d 31 0d 0a 0d 0a 3c 21 44 4f   o-8859-1....<!DO
  00e0  43 54 59 50 45 20 48 54 4d 4c 20 50 55 42 4c 49   CTYPE HTML PUBLI
  00f0  43 20 22 2d 2f 2f 49 45 54 46 2f 2f 44 54 44 20   C "-//IETF//DTD
  0100  48 54 4d 4c 20 32 2e 30 2f 2f 45 4e 22 3e 0a 3c   HTML 2.0//EN">.<
  0110  68 74 6d 6c 3e 3c 68 65 61 64 3e 0a 3c 74 69 74   html><head>.<tit
  0120  6c 65 3e 34 30 30 20 42 61 64 20 52 65 71 75 65   le>400 Bad Reque
  0130  73 74 3c 2f 74 69 74 6c 65 3e 0a 3c 2f 68 65 61   st</title>.</hea
  0140  64 3e 3c 62 6f 64 79 3e 0a 3c 68 31 3e 42 61 64   d><body>.<h1>Bad
  0150  20 52 65 71 75 65 73 74 3c 2f 68 31 3e 0a 3c 70    Request</h1>.<p
  0160  3e 59 6f 75 72 20 62 72 6f 77 73 65 72 20 73 65   >Your browser se
  0170  6e 74 20 61 20 72 65 71 75 65 73 74 20 74 68 61   nt a request tha
  0180  74 20 74 68 69 73 20 73 65 72 76 65 72 20 63 6f   t this server co
  0190  75 6c 64 20 6e 6f 74 20 75 6e 64 65 72 73 74 61   uld not understa
  01a0  6e 64 2e 3c 62 72 20 2f 3e 0a 3c 2f 70 3e 0a 3c   nd.<br />.</p>.<
  01b0  68 72 3e 0a 3c 61 64 64 72 65 73 73 3e 41 70 61   hr>.<address>Apa
  01c0  63 68 65 20 53 65 72 76 65 72 20 61 74 20 76 69   che Server at vi
  01d0  72 74 75 61 6c 68 6f 73 74 2e 31 38 34 2e 31 36   rtualhost.184.16
  01e0  38 2e 31 37 36 2e 31 20 50 6f 72 74 20 38 30 3c   8.176.1 Port 80<
  01f0  2f 61 64 64 72 65 73 73 3e 0a 3c 2f 62 6f 64 79   /address>.</body
  0200  3e 3c 2f 68 74 6d 6c 3e 0a                        ></html>.

You can see the HTTP headers and page content in the payload of this frame. I
bolded the hex and ASCII output for the ``HTT`` part of the HTTP header in the
payload. :program:`tshark` reports a warning as seen in the bolded output.

:file:`conn.log`
----------------

Here is the :file:`conn.log` that Zeek generated for this activity:

.. literal-emph::

  {
    "ts": 1607568264.274569,
    **"uid": "C8blOJ21azairPrWf8",**
    "id.orig_h": "192.168.4.142",
    "id.orig_p": 50540,
    "id.resp_h": "184.168.176.1",
    "id.resp_p": 443,
    "proto": "tcp",
    "duration": 0.1382908821105957,
    "orig_bytes": 524,
    "resp_bytes": 467,
    "conn_state": "SF",
    "missed_bytes": 0,
    "history": "ShADadfF",
    "orig_pkts": 6,
    "orig_ip_bytes": 776,
    "resp_pkts": 5,
    "resp_ip_bytes": 675
  }

The :file:`conn.log` entry is fairly normal.

:file:`ssl.log`
---------------

Here is the :file:`ssl.log` that Zeek generated for this activity:

.. literal-emph::

  {
    "ts": 1607568264.340668,
    "uid": "C8blOJ21azairPrWf8",
    "id.orig_h": "192.168.4.142",
    "id.orig_p": 50540,
    "id.resp_h": "184.168.176.1",
    "id.resp_p": 443,
    "server_name": "usafaikidonews.com",
    "resumed": false,
    **"established": false**
  }

The :file:`ssl.log` shows that a TLS encrypted session was not established.

:file:`dpd.log`
---------------

Here is the :file:`dpd.log` that Zeek generated for this activity:

.. literal-emph::

  {
    "ts": 1607568264.410681,
    "uid": "C8blOJ21azairPrWf8",
    "id.orig_h": "192.168.4.142",
    "id.orig_p": 50540,
    "id.resp_h": "184.168.176.1",
    "id.resp_p": 443,
    "proto": "tcp",
    **"analyzer": "SSL",**
    **"failure_reason": "Invalid version late in TLS connection. Packet reported version: 21588"**
  }

Here we see that DPD and the SSL analyzer report an error in the TLS
connection, as expected. The question is, to what does ``version: 21588``
refer?

Decoding 21588
==============

Let’s take a look at part of frame 9, which is the TLS client hello:

.. literal-emph::

  Secure Sockets Layer
      TLSv1 Record Layer: Handshake Protocol: Client Hello
          **Content Type: Handshake (22)**
          **Version: TLS 1.0 (0x0301)**
          Length: 512
          Handshake Protocol: Client Hello
              Handshake Type: Client Hello (1)
              Length: 508
              **Version: TLS 1.2 (0x0303)**
  ...truncated...

  0000  fc ec da 49 e0 10 60 f2 62 3c 9c 68 08 00 45 00   ...I..`.b<.h..E.
  0010  02 2d 97 6c 40 00 80 06 33 7e c0 a8 04 8e b8 a8   .-.l@...3~......
  0020  b0 01 c5 6c 01 bb 09 bd 1c 5f e8 a2 c2 eb 50 18   ...l....._....P.
  0030  02 01 6e 33 00 00 **16 03 01** 02 00 01 00 01 fc **03**   ..n3............
  0040  **03** 97 16 82 4f e0 ff e3 3e 6f d8 33 28 9a 97 b8   ....O...>o.3(...
  0050  1a f0 73 6b 12 98 af 25 e2 a5 bc 6c 2e aa b1 69   ..sk...%...l...i
  0060  be 20 bf d4 27 c5 22 bf 0d 90 83 24 80 36 ad 11   . ..'."....$.6..
  0070  17 8a 2d a2 a1 42 1d ef 6b 1f ef ce cf 9a e2 f5   ..-..B..k.......
  0080  be 79 00 20 2a 2a 13 01 13 02 13 03 c0 2b c0 2f   .y. **.......+./
  0090  c0 2c c0 30 cc a9 cc a8 c0 13 c0 14 00 9c 00 9d   .,.0............
  00a0  00 2f 00 35 01 00 01 93 ca ca 00 00 00 00 00 17   ./.5............
  00b0  00 15 00 00 12 75 73 61 66 61 69 6b 69 64 6f 6e   .....usafaikidon
  00c0  65 77 73 2e 63 6f 6d 00 17 00 00 ff 01 00 01 00   ews.com.........

I’ve bolded a few points. The important ones are ``0x160301``. These are the
values indicating a TLS handshake and TLS 1.0. This is apparently not an
attempt at a TLS 1.0 connection, however, as the second bolded hex value of
``0x0303`` shows TLS 1.2 in play.

Now, compare this output with what appeared in the odd “HTTP” frame shown
earlier:

.. literal-emph::

  0000  60 f2 62 3c 9c 68 fc ec da 49 e0 10 08 00 45 00   `.b<.h...I....E.
  0010  01 fb cc 4e 40 00 37 06 47 ce b8 a8 b0 01 c0 a8   ...N@.7.G.......
  0020  04 8e 01 bb c5 6c e8 a2 c2 eb 09 bd 1e 64 50 18   .....l.......dP.
  0030  00 3e de 95 00 00 **48 54 54** 50 2f 31 2e 31 20 34   .>....**HTT**P/1.1 4
  0040  30 30 20 42 61 64 20 52 65 71 75 65 73 74 0d 0a   00 Bad Request..

The ``0x48`` value is in the location where a TLS content type message would
sit.  In the previous frame, the value was ``0x16``, for a handshake. Here it
is ``0x48``, which is ASCII letter H. Next we see ``0x5454``, which is ASCII
letters ``T T``. In decimal, the value for ``0x5454`` is 21588. In other words,
where Zeek was looking to find a TLS version, it found decimal 21588. In the
previous frame, the corresponding value was ``0x0301`` for TLSv1.0. That is why
Zeek generated an error in its :file:`dpd.log` with the message "Invalid
version late in TLS connection. Packet reported version: 21588".

Assorted Examples
=================

The following represents a summary of some :file:`dpd.log` entries, sorted by count,
observed in my reference network.

.. code-block:: console

  $ find ./corelightswslogs/ -name "dpd*20**.gz" | while read -r file; do zcat -f "$file"; done | jq -c '[."proto", ."analyzer", ."failure_reason"]' | sort | uniq -c | sort -nr

::

   165341 ["tcp","HTTP","not a http reply line"]
      162 ["tcp","SSL","Invalid version late in TLS connection. Packet reported version: 0"]
      114 ["tcp","SSL","Invalid version late in TLS connection. Packet reported version: 21588"]
       36 ["tcp","SSL","Invalid version late in TLS connection. Packet reported version: 25344"]
       28 ["udp","NTP","Binpac exception: binpac exception: out_of_bound: Extension_Field:value: 3476019 > 52"]
       17 ["udp","SIP","Binpac exception: binpac exception: string mismatch at /bro/src/analyzer/protocol/sip/sip-protocol.pac:43: \nexpected pattern: \"SIP/\"\nactual data: \"\\x05\""]
        9 ["tcp","SSL","Invalid version late in TLS connection. Packet reported version: 8516"]
        8 ["udp","SIP","Binpac exception: binpac exception: string mismatch at /bro/src/analyzer/protocol/sip/sip-protocol.pac:43: \nexpected pattern: \"SIP/\"\nactual data: \"\\x01\""]
  ...edited...
        1 ["udp","SIP","Binpac exception: binpac exception: out_of_bound: SIP_Version:anonymous_field_009: 4 > 2"]
        1 ["udp","DTLS","Invalid version in DTLS connection. Packet reported version: 59228"]
        1 ["udp","DTLS","Invalid version in DTLS connection. Packet reported version: 52736"]
        1 ["udp","DTLS","Invalid version in DTLS connection. Packet reported version: 52480"]
        1 ["tcp","SSL","Invalid version late in TLS connection. Packet reported version: 5123"]
        1 ["tcp","SSL","Invalid version late in TLS connection. Packet reported version: 40499"]
        1 ["tcp","IRC","too many long lines"]

As you can see, Zeek saw problems with HTTP, SSL, NTP, Session Initiation
Protocol (SIP), Datagram Transport Layer Security (DTLS), and IRC.

Conclusion
==========

Zeek’s :file:`dpd.log` may help analysts identify suspicious activity,
depending on how it violates Zeek’s protocol parsers. In that sense, it is sort
of a specialized version of Zeek’s :file:`weird.log`. Periodic analysis of the
entries may identify traffic worthy of additional investigation.
