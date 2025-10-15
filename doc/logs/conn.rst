========
conn.log
========

The connection log, or :file:`conn.log`, is one of the most important logs Zeek
creates. It may seem like the idea of a “connection” is most closely associated
with stateful protocols like Transmission Control Protocol (TCP), unlike
stateless protocols like User Datagram Protocol (UDP). Zeek’s :file:`conn.log`,
however, tracks both sorts of protocols. This section of the manual will
explain key elements of the :file:`conn.log`.

The Zeek script reference, derived from the Zeek code, completely explains the
meaning of each field in the :file:`conn.log` (and other logs). It would be
duplicative to manually recreate that information in another format here.
Therefore, this entry seeks to show how an analyst would make use of the
information in the conn.log. Those interested in getting details on every
element of the :file:`conn.log` should reference :zeek:see:`Conn::Info`.
For additional explanation, including Zeek's notions of originator and
responder, see :ref:`writing-scripts-connection-record`.

Throughout the sections that follow, we will inspect Zeek logs in JSON format.

Inspecting the :file:`conn.log`
===============================

To inspect the :file:`conn.log`, we will use the same techniques we learned in
the last section of the manual. First, we have a JSON-formatted log file,
either collected by Zeek watching a live interface, or by Zeek processing
stored traffic. We use the :program:`jq` utility to review the contents.

.. code-block:: console

  zeek@zeek:~zeek-test/json$ jq . -c conn.log

::

  {"ts":1591367999.305988,"uid":"CMdzit1AMNsmfAIiQc","id.orig_h":"192.168.4.76","id.orig_p":36844,"id.resp_h":"192.168.4.1","id.resp_p":53,"proto":"udp","service":"dns","duration":0.06685185432434082,"orig_bytes":62,"resp_bytes":141,"conn_state":"SF","missed_bytes":0,"history":"Dd","orig_pkts":2,"orig_ip_bytes":118,"resp_pkts":2,"resp_ip_bytes":197}

  {"ts":1591367999.430166,"uid":"C5bLoe2Mvxqhawzqqd","id.orig_h":"192.168.4.76","id.orig_p":46378,"id.resp_h":"31.3.245.133","id.resp_p":80,"proto":"tcp","service":"http","duration":0.25411510467529297,"orig_bytes":77,"resp_bytes":295,"conn_state":"SF","missed_bytes":0,"history":"ShADadFf","orig_pkts":6,"orig_ip_bytes":397,"resp_pkts":4,"resp_ip_bytes":511}

Alternatively, we could see each field printed on its own line:

.. code-block:: console

  zeek@zeek:~zeek-test/json$ jq . conn.log

::

  {
    "ts": 1591367999.305988,
    "uid": "CMdzit1AMNsmfAIiQc",
    "id.orig_h": "192.168.4.76",
    "id.orig_p": 36844,
    "id.resp_h": "192.168.4.1",
    "id.resp_p": 53,
    "proto": "udp",
    "service": "dns",
    "duration": 0.06685185432434082,
    "orig_bytes": 62,
    "resp_bytes": 141,
    "conn_state": "SF",
    "missed_bytes": 0,
    "history": "Dd",
    "orig_pkts": 2,
    "orig_ip_bytes": 118,
    "resp_pkts": 2,
    "resp_ip_bytes": 197
  }
  {
    "ts": 1591367999.430166,
    "uid": "C5bLoe2Mvxqhawzqqd",
    "id.orig_h": "192.168.4.76",
    "id.orig_p": 46378,
    "id.resp_h": "31.3.245.133",
    "id.resp_p": 80,
    "proto": "tcp",
    "service": "http",
    "duration": 0.25411510467529297,
    "orig_bytes": 77,
    "resp_bytes": 295,
    "conn_state": "SF",
    "missed_bytes": 0,
    "history": "ShADadFf",
    "orig_pkts": 6,
    "orig_ip_bytes": 397,
    "resp_pkts": 4,
    "resp_ip_bytes": 511
  }

What an analyst derives from any log is a function of the questions that he or
she is trying to ask of it. The :file:`conn.log` primarily captures so-called
“layer 3” and “layer 4” elements of network activity. This is essentially who
is talking to whom, when, for how long, and with what protocol.

Understanding the Second :file:`conn.log` Entry
===============================================

Let’s use this framework to parse the two log entries. We will start with the
second entry first. I will explain why shortly. For reference, that entry is
the following:

::

  {
    "ts": 1591367999.430166,
    "uid": "C5bLoe2Mvxqhawzqqd",
    "id.orig_h": "192.168.4.76",
    "id.orig_p": 46378,
    "id.resp_h": "31.3.245.133",
    "id.resp_p": 80,
    "proto": "tcp",
    "service": "http",
    "duration": 0.25411510467529297,
    "orig_bytes": 77,
    "resp_bytes": 295,
    "conn_state": "SF",
    "missed_bytes": 0,
    "history": "ShADadFf",
    "orig_pkts": 6,
    "orig_ip_bytes": 397,
    "resp_pkts": 4,
    "resp_ip_bytes": 511
  }

For the second log, ``192.168.4.76`` talked to ``31.3.245.133``.

The log *timestamp*, indicated by the ``ts`` field, is ``1591367999.430166``,
which translates as shown below, courtesy of the Unix :program:`date` command:

.. code-block:: console

  zeek@zeek:~zeek-test/json$ date -d @"1591367999.430166"

::

  Fri Jun  5 14:39:59 UTC 2020

The two systems conversation only lasted ``0.25411510467529297`` seconds. (The
operating system provides this value.)

They spoke the HyperText Transfer Protocol (HTTP), identified by Zeek as HTTP
over TCP using TCP port 80 listening on ``31.3.245.133``.

If we wanted to move beyond who talked with whom, when, for how long, and with
what protocol, the second conn.log entry offers a few more items of interest.
For example, we know that ``192.168.4.76`` sent 77 bytes of data in its application
layer payload, and 397 bytes in its IP layer payload.

We can verify that 77 byte figure by decoding the HTTP traffic sent from
``192.168.4.76`` during this session. We use :program:`tshark`, the command
line version of Wireshark, to do so.

.. code-block:: console

  zeek@zeek:~zeek-test/json$ tshark -V -r ../../tmi1.pcap http and ip.src==192.168.4.76

.. literal-emph::

  Frame 21: 143 bytes on wire (1144 bits), 143 bytes captured (1144 bits)
      Encapsulation type: Ethernet (1)
      Arrival Time: Jun  5, 2020 14:39:59.512593000 UTC
      [Time shift for this packet: 0.000000000 seconds]
      Epoch Time: 1591367999.512593000 seconds
      [Time delta from previous captured frame: 0.000309000 seconds]
      [Time delta from previous displayed frame: 0.000000000 seconds]
      [Time since reference or first frame: 17.461008000 seconds]
      Frame Number: 21
      Frame Length: 143 bytes (1144 bits)
      Capture Length: 143 bytes (1144 bits)
      [Frame is marked: False]
      [Frame is ignored: False]
      [Protocols in frame: eth:ethertype:ip:tcp:http]
  Ethernet II, Src: 08:00:27:97:99:0d, Dst: fc:ec:da:49:e0:10
      Destination: fc:ec:da:49:e0:10
          Address: fc:ec:da:49:e0:10
          .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
          .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
      Source: 08:00:27:97:99:0d
          Address: 08:00:27:97:99:0d
          .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
          .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
      Type: IPv4 (0x0800)
  Internet Protocol Version 4, **Src: 192.168.4.76, Dst: 31.3.245.133**
      0100 .... = Version: 4
      .... 0101 = Header Length: 20 bytes (5)
      Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)
          0000 00.. = Differentiated Services Codepoint: Default (0)
          .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)
      Total Length: 129
      Identification: 0xfdf1 (65009)
      Flags: 0x4000, Don't fragment
          0... .... .... .... = Reserved bit: Not set
          .1.. .... .... .... = Don't fragment: Set
          ..0. .... .... .... = More fragments: Not set
          ...0 0000 0000 0000 = Fragment offset: 0
      Time to live: 64
      Protocol: TCP (6)
      Header checksum: 0x6308 [validation disabled]
      [Header checksum status: Unverified]
      **Source: 192.168.4.76**
      **Destination: 31.3.245.133**
  Transmission Control Protocol, **Src Port: 46378, Dst Port: 80**, Seq: 1, Ack: 1, **Len: 77**
      **Source Port: 46378**
      **Destination Port: 80**
      [Stream index: 0]
      **[TCP Segment Len: 77]**
      Sequence number: 1    (relative sequence number)
      [Next sequence number: 78    (relative sequence number)]
      Acknowledgment number: 1    (relative ack number)
      1000 .... = Header Length: 32 bytes (8)
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
      Window size value: 32
      [Calculated window size: 65536]
      [Window size scaling factor: 2048]
      Checksum: 0xd9f0 [unverified]
      [Checksum Status: Unverified]
      Urgent pointer: 0
      Options: (12 bytes), No-Operation (NOP), No-Operation (NOP), Timestamps
          TCP Option - No-Operation (NOP)
              Kind: No-Operation (1)
          TCP Option - No-Operation (NOP)
              Kind: No-Operation (1)
          TCP Option - Timestamps: TSval 3137978878, TSecr 346747623
              Kind: Time Stamp Option (8)
              Length: 10
              Timestamp value: 3137978878
              Timestamp echo reply: 346747623
      [SEQ/ACK analysis]
          [iRTT: 0.082118000 seconds]
          **[Bytes in flight: 77]**
          [Bytes sent since last PSH flag: 77]
      [Timestamps]
          [Time since first frame in this TCP stream: 0.082427000 seconds]
          [Time since previous frame in this TCP stream: 0.000309000 seconds]
      **TCP payload (77 bytes)**
  Hypertext Transfer Protocol
      **GET / HTTP/1.1\r\n**
          [Expert Info (Chat/Sequence): GET / HTTP/1.1\r\n]
              [GET / HTTP/1.1\r\n]
              [Severity level: Chat]
              [Group: Sequence]
          Request Method: GET
          Request URI: /
          Request Version: HTTP/1.1
      **Host: testmyids.com\r\n**
      **User-Agent: curl/7.47.0\r\n**
      **Accept: */*\r\n**
      **\r\n**
      [Full request URI: http://testmyids.com/]
      [HTTP request 1/1]

In the highlighted output, we see that :program:`tshark` notes 77 bytes of data
carried by TCP from ``192.168.4.76``. I highlighted what that data was,
beginning with a GET request.

Another way to look at this TCP segment is to dump the hex contents using a
different :program:`tshark` option, as shown below.

.. code-block:: console

  zeek@zeek:~zeek-test/json$ tshark -x -r ../../tmi1.pcap http and ip.src==192.168.4.76

.. literal-emph::

  0000  fc ec da 49 e0 10 08 00 27 97 99 0d 08 00 45 00   ...I....'.....E.
  0010  00 81 fd f1 40 00 40 06 63 08 c0 a8 04 4c 1f 03   ....@.@.c....L..
  0020  f5 85 b5 2a 00 50 dd e8 f3 47 b2 71 7e 69 80 18   ...*.P...G.q~i..
  0030  00 20 d9 f0 00 00 01 01 08 0a bb 09 c1 fe 14 aa   . ..............
  0040  f2 e7 **47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31   ..GET / HTTP/1.1**
  0050  **0d 0a 48 6f 73 74 3a 20 74 65 73 74 6d 79 69 64   ..Host: testmyid**
  0060  **73 2e 63 6f 6d 0d 0a 55 73 65 72 2d 41 67 65 6e   s.com..User-Agen**
  0070  **74 3a 20 63 75 72 6c 2f 37 2e 34 37 2e 30 0d 0a   t: curl/7.47.0..**
  0080  **41 63 63 65 70 74 3a 20 2a 2f 2a 0d 0a 0d 0a      Accept: */***....

The hexadecimal values appear on the left, and the ASCII decode appears on the
right. If you count the highlighted hex values, you will find 77 of them, hence
the 77 bytes of application layer data carried by TCP.

The connection state field, ``conn_state``, showed that the connection
terminated normally, as depicted by the ``SF`` entry. This means that, for this
TCP session, both sides adopted a “graceful close” mechanism. If you remember
this trace from the last chapter, you’ll remember seeing that it opened with a
TCP three way handshake (SYN - SYN ACK - ACK) and terminated with a graceful
close (FIN ACK - FIN ACK - ACK).

Finally, the ``history`` field contains the string ``ShADadFf``. Remember that
capitalized letters indicate an action by the connection originator. Lowercase
letters indicate an action by the responder. This means that ``ShADadFf``
translates to the following:

::

  S - The originator sent a SYN segment.
  h - The responder sent a SYN ACK segment.
  A - The originator sent an ACK segment.
  D - The originator sent at least one segment with payload data. In this case, that was HTTP over TCP.
  a - The responder replied with an ACK segment.
  d - The responder replied with at least one segment with payload data.
  F - The originator sent a FIN ACK segment.
  f - The responder replied with a FIN ACK segment.

This log entry demonstrates how Zeek is able to pack so much information into a
compact representation.

Understanding the First :file:`conn.log` Entry
==============================================

Now let’s turn to the first :file:`conn.log` entry, reproduced below for easy
reference.

::

  {
    "ts": 1591367999.305988,
    "uid": "CMdzit1AMNsmfAIiQc",
    "id.orig_h": "192.168.4.76",
    "id.orig_p": 36844,
    "id.resp_h": "192.168.4.1",
    "id.resp_p": 53,
    "proto": "udp",
    "service": "dns",
    "duration": 0.06685185432434082,
    "orig_bytes": 62,
    "resp_bytes": 141,
    "conn_state": "SF",
    "missed_bytes": 0,
    "history": "Dd",
    "orig_pkts": 2,
    "orig_ip_bytes": 118,
    "resp_pkts": 2,
    "resp_ip_bytes": 197
  }

For the first entry, ``192.168.4.76`` talked to ``192.168.4.1``.

The log timestamp is ``1591367999.305988``, which translates as shown below,
courtesy of the Unix :program:`date` command:

.. code-block:: console

  zeek@zeek:~zeek-test/json$ date -d @"1591367999.305988"

::

  Fri Jun  5 14:39:59 UTC 2020

The two systems’ “conversation” only lasted ``0.06685185432434082`` seconds.
(Again, such precision!)

They spoke the Domain Name System (DNS) protocol, identified by Zeek as DNS
over UDP using UDP port 53 listening on ``192.168.4.1``.

The connection state for this conversation is listed as ``SF``, the same as the
TCP version. However, UDP has no concept of state, leaving that duty to a
higher level protocol. In the context of UDP, ``SF`` means that Zeek assesses
the conversations as “normal establishment and termination” of the
“connection.”

Similarly, the ``history`` field is simply ``Dd``, indicating that each party
to the conversation sent data to the other.

The ``uid`` and Other Fields
============================

Notice that both :file:`conn.log` entries contain ``uid`` fields. These are
unique identifiers assigned by Zeek that we will use to track related activity
in other transaction logs.

There are other fields which may appear in the :file:`conn.log`, depending on
the protocol being summarized. For details on the meaning of those fields, see
:zeek:see:`Conn::Info`.

Conclusion
==========

Zeek’s :file:`conn.log` is a foundational log that offers a great deal of
information on its own. However, it becomes even more useful when it acts as
the starting point for investigating related Zeek logs. We turn to that
capability in the following sections.
