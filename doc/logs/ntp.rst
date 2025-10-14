=======
ntp.log
=======

Network Time Protocol (NTP) is another core protocol found in IP networks. NTP
is a mechanism by which clients can adjust their local clocks to more closely
match those of NTP servers. Many devices ship with NTP clients already
configured to contact public NTP servers. Administrators can use Zeek logs to
identify NTP clients and servers, and determine if they are operating as
expected.

As with all entries in this document, for full explanation of each field in the
log, see :zeek:see:`NTP::Info`.

NTP via :program:`tcpdump`
==========================

NTP is a request-response protocol, as demonstrated by the following exchange
decoded by :program:`tcpdump`::

  00:29:07.927672 IP 192.168.4.49.38461 > 208.79.89.249.123: NTPv4, Client, length 48
  00:29:07.995844 IP 208.79.89.249.123 > 192.168.4.49.38461: NTPv4, Server, length 48

Using the verbose feature, we see the following details::

  00:29:07.927672 IP (tos 0x10, ttl 64, id 3186, offset 0, flags [DF], proto UDP (17), length 76)
      192.168.4.49.38461 > 208.79.89.249.123: [udp sum ok] NTPv4, length 48
          Client, Leap indicator:  (0), Stratum 0 (unspecified), poll 0 (1s), precision 0
          Root Delay: 0.000000, Root dispersion: 0.000000, Reference-ID: (unspec)
            Reference Timestamp:  0.000000000
            Originator Timestamp: 0.000000000
            Receive Timestamp:    0.000000000
            Transmit Timestamp:   3811105747.215585991 (2020/10/08 00:29:07)
              Originator - Receive Timestamp:  0.000000000
              Originator - Transmit Timestamp: 3811105747.215585991 (2020/10/08 00:29:07)

  00:29:07.995844 IP (tos 0x0, ttl 56, id 18045, offset 0, flags [DF], proto UDP (17), length 76)
      208.79.89.249.123 > 192.168.4.49.38461: [udp sum ok] NTPv4, length 48
          Server, Leap indicator:  (0), Stratum 2 (secondary reference), poll 3 (8s), precision -24
          Root Delay: 0.009216, Root dispersion: 0.021224, Reference-ID: 127.67.113.92
            Reference Timestamp:  3811105455.942204197 (2020/10/08 00:24:15)
            Originator Timestamp: 3811105747.215585991 (2020/10/08 00:29:07)
            Receive Timestamp:    3811105747.964280626 (2020/10/08 00:29:07)
            Transmit Timestamp:   3811105747.964314032 (2020/10/08 00:29:07)
              Originator - Receive Timestamp:  +0.748694635
              Originator - Transmit Timestamp: +0.748728040

A look at :rfc:`5905`, explaining NTPv4, helps us understand the timestamps
shown in the decoded output::

  LI Leap Indicator (leap): 2-bit integer warning of an impending leap second
  to be inserted or deleted in the last minute of the current month with values
  defined in Figure 9.

             +-------+----------------------------------------+
             | Value | Meaning                                |
             +-------+----------------------------------------+
             | 0     | no warning                             |
             | 1     | last minute of the day has 61 seconds  |
             | 2     | last minute of the day has 59 seconds  |
             | 3     | unknown (clock unsynchronized)         |
             +-------+----------------------------------------+

                           Figure 9: Leap Indicator

  VN Version Number (version): 3-bit integer representing the NTP version
  number, currently 4.

  Mode (mode): 3-bit integer representing the mode, with values defined in
  Figure 10.

                        +-------+--------------------------+
                        | Value | Meaning                  |
                        +-------+--------------------------+
                        | 0     | reserved                 |
                        | 1     | symmetric active         |
                        | 2     | symmetric passive        |
                        | 3     | client                   |
                        | 4     | server                   |
                        | 5     | broadcast                |
                        | 6     | NTP control message      |
                        | 7     | reserved for private use |
                        +-------+--------------------------+

                         Figure 10: Association Modes

  Stratum (stratum): 8-bit integer representing the stratum, with values
  defined in Figure 11.

          +--------+-----------------------------------------------------+
          | Value  | Meaning                                             |
          +--------+-----------------------------------------------------+
          | 0      | unspecified or invalid                              |
          | 1      | primary server (e.g., equipped with a GPS receiver) |
          | 2-15   | secondary server (via NTP)                          |
          | 16     | unsynchronized                                      |
          | 17-255 | reserved                                            |
          +--------+-----------------------------------------------------+

                           Figure 11: Packet Stratum

  Poll: 8-bit signed integer representing the maximum interval between
  successive messages, in log2 seconds.

  Precision: 8-bit signed integer representing the precision of the system
  clock, in log2 seconds. For instance, a value of -18 corresponds to a
  precision of about one microsecond.

  Root Delay (rootdelay): Total round-trip delay to the reference clock, in NTP
  short format.

  Root Dispersion (rootdisp): Total dispersion to the reference clock, in NTP
  short format.

  Reference ID (refid): 32-bit code identifying the particular server or
  reference clock.

  Reference Timestamp: Time when the system clock was last set or corrected, in
  NTP timestamp format.

  Origin Timestamp (org): Time at the client when the request departed for the
  server, in NTP timestamp format.

  Receive Timestamp (rec): Time at the server when the request arrived from the
  client, in NTP timestamp format.

  Transmit Timestamp (xmt): Time at the server when the response left for the
  client, in NTP timestamp format.

  Destination Timestamp (dst): Time at the client when the reply arrived from
  the server, in NTP timestamp format.

It makes sense that the reference, originator, and receive timestamps would be
zero in the client request, but non-zero in the server reply.

NTP via :program:`tcpdump` and :program:`tshark`
================================================

Let’s look at :program:`tshark`’s decode for the NTP-specific data, to see if
:program:`tcpdump` missed anything::

  Client to server:

  Network Time Protocol (NTP Version 4, client)
      Flags: 0x23, Leap Indicator: no warning, Version number: NTP Version 4, Mode: client
          00.. .... = Leap Indicator: no warning (0)
          ..10 0... = Version number: NTP Version 4 (4)
          .... .011 = Mode: client (3)
      Peer Clock Stratum: unspecified or invalid (0)
      Peer Polling Interval: invalid (0)
      Peer Clock Precision: 1.000000 sec
      Root Delay: 0 seconds
      Root Dispersion: 0 seconds
      Reference ID: NULL
      Reference Timestamp: Jan  1, 1970 00:00:00.000000000 UTC
      Origin Timestamp: Jan  1, 1970 00:00:00.000000000 UTC
      Receive Timestamp: Jan  1, 1970 00:00:00.000000000 UTC
      Transmit Timestamp: Oct  8, 2020 00:29:07.215585991 UTC

  Server to client:

  Network Time Protocol (NTP Version 4, server)
      Flags: 0x24, Leap Indicator: no warning, Version number: NTP Version 4, Mode: server
          00.. .... = Leap Indicator: no warning (0)
          ..10 0... = Version number: NTP Version 4 (4)
          .... .100 = Mode: server (4)
      Peer Clock Stratum: secondary reference (2)
      Peer Polling Interval: invalid (3)
      Peer Clock Precision: 0.000000 sec
      Root Delay: 0.00921630859375 seconds
      Root Dispersion: 0.0212249755859375 seconds
      Reference ID: 127.67.113.92
      Reference Timestamp: Oct  8, 2020 00:24:15.942204197 UTC
      Origin Timestamp: Oct  8, 2020 00:29:07.215585991 UTC
      Receive Timestamp: Oct  8, 2020 00:29:07.964280626 UTC
      Transmit Timestamp: Oct  8, 2020 00:29:07.964314032 UTC

It does not appear that :program:`tshark` reveals any details that
:program:`tcpdump` did not. One difference is that for the client reference,
origin, and receive timestamps, Tshark renders the 0 values as the Unix epoch,
i.e., ``Jan  1, 1970 00:00:00.000000000 UTC``.

NTP via Zeek
============

Here is how Zeek summarizes this NTP activity:

.. literal-emph::

  {
    "ts": "2020-10-08T00:29:07.977170Z",
    "uid": "CqlPpF1AQVLMPgGiL5",
    "id.orig_h": "192.168.4.49",
    "id.orig_p": 38461,
    "id.resp_h": "208.79.89.249",
    "id.resp_p": 123,
    "version": 4,
    **"mode": 3,**
    "stratum": 0,
    "poll": 1,
    "precision": 1,
    "root_delay": 0,
    "root_disp": 0,
    "ref_id": "\\x00\\x00\\x00\\x00",
    "ref_time": "1970-01-01T00:00:00.000000Z",
    "org_time": "1970-01-01T00:00:00.000000Z",
    "rec_time": "1970-01-01T00:00:00.000000Z",
    "xmt_time": "2020-10-08T00:29:07.215586Z",
    "num_exts": 0
  }

  {
    "ts": "2020-10-08T00:29:08.081209Z",
    "uid": "CqlPpF1AQVLMPgGiL5",
    "id.orig_h": "192.168.4.49",
    "id.orig_p": 38461,
    "id.resp_h": "208.79.89.249",
    "id.resp_p": 123,
    "version": 4,
    **"mode": 4,**
    "stratum": 2,
    "poll": 8,
    "precision": 5.960464477539063e-08,
    "root_delay": 0.00921630859375,
    "root_disp": 0.0212249755859375,
    "ref_id": "127.67.113.92",
    "ref_time": "2020-10-08T00:24:15.942204Z",
    "org_time": "2020-10-08T00:29:07.215586Z",
    "rec_time": "2020-10-08T00:29:07.964281Z",
    "xmt_time": "2020-10-08T00:29:07.964314Z",
    "num_exts": 0
  }

By looking at the mode field in each log, we see that the first entry is a NTP
client request (mode 3), and the second is the server’s reply (mode 4).

These log entries make an interesting comparison with those for DHCP. Zeek’s
DHCP logs seek to summarize potentially up to four individual datagrams (for
the DORA exchange) into one log entry. In contrast, Zeek’s NTP logs create an
entry for each NTP message.

Identifying NTP Servers
=======================

As with DHCP servers, Zeek can help identify NTP servers used by clients. The
following query shows a subset of systems and the NTP servers they have
queried:

.. code-block:: console

  $ find . -name "ntp**.gz" | while read -r file; do zcat -f "$file"; done | jq -c '[."id.orig_h", ."id.resp_h"]' | sort | uniq -c | sort -nr | head -10

::

    570 ["192.168.4.48","193.0.0.229"]
    271 ["192.168.4.76","91.189.91.157"]
    271 ["192.168.4.76","216.229.0.50"]
    270 ["192.168.4.76","74.6.168.73"]
    270 ["192.168.4.76","72.30.35.88"]
    270 ["192.168.4.76","38.229.71.1"]
    216 ["192.168.4.149","84.16.73.33"]
    206 ["192.168.4.48","50.205.244.21"]
    164 ["192.168.4.57","216.239.35.12"]
    162 ["192.168.4.57","216.239.35.8"]

The following query summarizes only the NTP servers seen by Zeek:

.. code-block:: console

  $ find . -name "ntp**.gz" | while read -r file; do zcat -f "$file"; done | jq -c '[."id.resp_h"]' | sort | uniq -c | sort -nr | head -10

::

    570 ["193.0.0.229"]
    470 ["17.253.20.253"]
    468 ["17.253.20.125"]
    357 ["91.189.91.157"]
    287 ["216.229.0.50"]
    286 ["74.6.168.73"]
    276 ["72.30.35.88"]
    270 ["38.229.71.1"]
    221 ["84.16.73.33"]
    206 ["50.205.244.21"]

Security and network administrators can use queries like this to identify
systems that are polling unauthorized NTP servers.

Conclusion
==========

NTP is an important protocol for modern network administration. Without
accurate clocks, many systems will not be able to complete cryptographic
exchanges. Be sure systems are kept up to date using the NTP servers you expect
them to query.
