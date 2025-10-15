========
dhcp.log
========

Dynamic Host Configuration Protocol is a core protocol found in Internet
Protocol (IP) networks. Using the protocol, DHCP servers provide clients with
IP addresses and other key information needed to make use of the network. This
entry will describe some aspects of Zeek’s dhcp.log that may be of use to
network and security personnel.

As with all entries in this document, for full explanation of each field in the
log, see :zeek:see:`DHCP::Info`.

DORA via Tcpdump
================

The method by which a client requests and receives an IP address and other
parameters from a DHCP server is represented by the acronym DORA. DORA stands
for Discover - Offer - Request - Acknowledge. The following :program:`tcpdump`
output of a complete DORA exchange demonstrates this protocol in action.

.. code-block:: console

  $ tcpdump -n -r snort.log.1601610971.bootp.pcap

.. literal-emph::

  reading from file snort.log.1601610971.bootp.pcap, link-type EN10MB (Ethernet)

  04:14:39.119370 IP **0.0.0.0.68 > 255.255.255.255.67**: BOOTP/DHCP, Request from 3c:58:c2:2f:91:21, length 302
  04:14:39.120138 IP **192.168.4.1.67 > 192.168.4.152.68**: BOOTP/DHCP, Reply, length 302
  04:14:39.158211 IP **0.0.0.0.68 > 255.255.255.255.67**: BOOTP/DHCP, Request from 3c:58:c2:2f:91:21, length 337
  04:14:39.456915 IP **192.168.4.1.67 > 192.168.4.152.68**: BOOTP/DHCP, Reply, length 302

The default output for :program:`tcpdump` doesn’t say much, other than showing
the IP addresses (or lack thereof, in the case of the ``0.0.0.0``` source IP
addresses). It is helpful to see this “simplified” output, however, before
delving into the details. It is slightly deceptive in the “request” and “reply”
messages, as strictly speaking these are more detailed and are DORA messages.

DORA via Tcpdump Verbose Mode
=============================

We can add the ``-vvv`` flag to :program:`tcpdump` to provide more verbose
output, as shown in the examples that follow.

The first datagram shows that a host that does not have an IP address set
(i.e., it’s using ``0.0.0.0``) sends a broadcast to ``255.255.255.255`` on port
67 UDP.  This client has had an IP address before as shown by its request for
``192.168.4.152``. Note the hostname and the presence of a Microsoft 5.0 vendor
class.

This is a DHCP Discover message from a client to any DHCP server listening on
the local network:

.. literal-emph::

  04:14:39.119370 IP (tos 0x0, ttl 128, id 44414, offset 0, flags [none], **proto UDP** (17), length 330)
      **0.0.0.0.68 > 255.255.255.255.67**: [udp sum ok] BOOTP/DHCP, Request from 3c:58:c2:2f:91:21, length 302, **xid 0xfd9859a7**, Flags [none] (0x0000)
            **Client-Ethernet-Address 3c:58:c2:2f:91:21**
            Vendor-rfc1048 Extensions
              Magic Cookie 0x63825363
              **DHCP-Message Option 53, length 1: Discover**
              Client-ID Option 61, length 7: ether 3c:58:c2:2f:91:21
              **Requested-IP Option 50, length 4: 192.168.4.152**
              **Hostname Option 12, length 15: "3071N0098017422"**
              **Vendor-Class Option 60, length 8: "MSFT 5.0"**
              Parameter-Request Option 55, length 14:
                Subnet-Mask, Default-Gateway, Domain-Name-Server, Domain-Name
                Router-Discovery, Static-Route, Vendor-Option, Netbios-Name-Server
                Netbios-Node, Netbios-Scope, Option 119, Classless-Static-Route
                Classless-Static-Route-Microsoft, Option 252
              END Option 255, length 0

The second datagram is a reply from the local DHCP server running on
``192.168.4.1``. The server replies directly to ``192.168.4.152``, which in
this case will end up at the system using MAC address ``3c:58:c2:2f:91:21``,
such that the destination IP address is probably not relevant here. Remember
that if the client at MAC address ``3c:58:c2:2f:91:21`` had no IP address to
begin with, it would only receive the DHCP offer by virtue of the DHCP offer
datagram being addressed to its MAC address. The server is not offering a
specified domain name other than “localdomain.”

This is a DHCP Offer message, from the DHCP server to the client:

.. literal-emph::

  04:14:39.120138 IP (tos 0x10, ttl 128, id 0, offset 0, flags [none], proto UDP (17), length 330)
      **192.168.4.1.67 > 192.168.4.152.68**: [udp sum ok] **BOOTP/DHCP, Reply**, length 302, **xid 0xfd9859a7**, Flags [none] (0x0000)
            **Your-IP 192.168.4.152**
            **Client-Ethernet-Address 3c:58:c2:2f:91:21**
            Vendor-rfc1048 Extensions
              Magic Cookie 0x63825363
              **DHCP-Message Option 53, length 1: Offer**
              **Server-ID Option 54, length 4: 192.168.4.1**
              **Lease-Time Option 51, length 4: 86400**
              **Subnet-Mask Option 1, length 4: 255.255.255.0**
              **Default-Gateway Option 3, length 4: 192.168.4.1**
              **Domain-Name-Server Option 6, length 4: 192.168.4.1**
              Domain-Name Option 15, length 11: "localdomain"
              T119 Option 119, length 13: 11.108.111.99.97.108.100.111.109.97.105.110.0
              END Option 255, length 0

The third datagram is a reply to the server’s reply. Here the client requests
the IP address ``192.168.4.152``. We also see it provide a fully qualified
domain name (FQDN) for itself, belonging to the FCPS educational domain. Again
note the client does not include an IP address for itself in the layer 3
header. It uses ``0.0.0.0`` as in the initial Discover message.

This is a DHCP Request message from the client to the DHCP server:

.. literal-emph::

  04:14:39.158211 IP (tos 0x0, ttl 128, id 44415, offset 0, flags [none], proto UDP (17), length 365)
      **0.0.0.0.68 > 255.255.255.255.67**: [udp sum ok] **BOOTP/DHCP, Request from 3c:58:c2:2f:91:21**, length 337, **xid 0xfd9859a7**, Flags [none] (0x0000)
            **Client-Ethernet-Address 3c:58:c2:2f:91:21**
            Vendor-rfc1048 Extensions
              Magic Cookie 0x63825363
              **DHCP-Message Option 53, length 1: Request**
              **Client-ID Option 61, length 7: ether 3c:58:c2:2f:91:21**
              **Requested-IP Option 50, length 4: 192.168.4.152**
              **Server-ID Option 54, length 4: 192.168.4.1**
              Hostname Option 12, length 15: "3071N0098017422"
              **FQDN Option 81, length 27: "3071N0098017422.fcps.edu"**
              **Vendor-Class Option 60, length 8: "MSFT 5.0"**
              Parameter-Request Option 55, length 14:
                Subnet-Mask, Default-Gateway, Domain-Name-Server, Domain-Name
                Router-Discovery, Static-Route, Vendor-Option, Netbios-Name-Server
                Netbios-Node, Netbios-Scope, Option 119, Classless-Static-Route
                Classless-Static-Route-Microsoft, Option 252
              END Option 255, length 0

Finally the server sends its last message, essentially confirming the
information sent in the DHCP Offer message. Note that :program:`tcpdump` is
unable to make sense of what it renders as ``T119 Option 119``. We will return
to that shortly.

This is a DHCP Acknowledgement message, sent from the DHCP server to the client:

.. literal-emph::

  04:14:39.456915 IP (tos 0x10, ttl 128, id 0, offset 0, flags [none], proto UDP (17), length 330)
      **192.168.4.1.67 > 192.168.4.152.68**: [udp sum ok] **BOOTP/DHCP, Reply**, length 302, xid 0xfd9859a7, Flags [none] (0x0000)
            **Your-IP 192.168.4.152**
            **Client-Ethernet-Address 3c:58:c2:2f:91:21**
            Vendor-rfc1048 Extensions
              Magic Cookie 0x63825363
              **DHCP-Message Option 53, length 1: ACK**
              **Server-ID Option 54, length 4: 192.168.4.1**
              **Lease-Time Option 51, length 4: 86400**
              **Subnet-Mask Option 1, length 4: 255.255.255.0**
              **Default-Gateway Option 3, length 4: 192.168.4.1**
              **Domain-Name-Server Option 6, length 4: 192.168.4.1**
              Domain-Name Option 15, length 11: "localdomain"
              T119 Option 119, length 13: 11.108.111.99.97.108.100.111.109.97.105.110.0
              END Option 255, length 0

Acknowledgement via :program:`tshark`
=====================================

We could look at the entire trace using :program:`tshark` (the command line
version of Wireshark), but it would largely be redundant. Rather, I would like
to look at the Acknowledgment message to explain about the T119 Option that
:program:`tcpdump` could not decode.

To find the datagram of interest, I tell :program:`tshark` to read the packet
capture of interest. I tell it to look for the “bootp” transaction identifier
associated with the DORA exchange of interest. (BOOTP refers to Bootstrap, a
precursor protocol that Tshark still uses for DHCP filters.) I also tell
:program:`tshark` to look for the specific BOOTP (DHCP) option value (5)
associated with the ACK message.

.. code-block:: console

  $ tshark -V -n -r snort.log.1601610971.bootp.pcap bootp.id == 0xfd9859a7 and bootp.option.dhcp == 5

.. literal-emph::

  Frame 4: 344 bytes on wire (2752 bits), 344 bytes captured (2752 bits) on interface 0
      Interface id: 0 (unknown)
          Interface name: unknown
      Encapsulation type: Ethernet (1)
      Arrival Time: Oct  2, 2020 04:14:39.456915000 UTC
      [Time shift for this packet: 0.000000000 seconds]
      Epoch Time: 1601612079.456915000 seconds
      [Time delta from previous captured frame: 0.298704000 seconds]
      [Time delta from previous displayed frame: 0.000000000 seconds]
      [Time since reference or first frame: 0.337545000 seconds]
      Frame Number: 4
      Frame Length: 344 bytes (2752 bits)
      Capture Length: 344 bytes (2752 bits)
      [Frame is marked: False]
      [Frame is ignored: False]
      [Protocols in frame: eth:ethertype:ip:udp:bootp]
  **Ethernet II, Src: fc:ec:da:49:e0:10, Dst: 3c:58:c2:2f:91:21**
      Destination: 3c:58:c2:2f:91:21
          Address: 3c:58:c2:2f:91:21
          .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
          .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
      Source: fc:ec:da:49:e0:10
          Address: fc:ec:da:49:e0:10
          .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
          .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
      Type: IPv4 (0x0800)
  **Internet Protocol Version 4, Src: 192.168.4.1, Dst: 192.168.4.152**
      0100 .... = Version: 4
      .... 0101 = Header Length: 20 bytes (5)
      Differentiated Services Field: 0x10 (DSCP: Unknown, ECN: Not-ECT)
          0001 00.. = Differentiated Services Codepoint: Unknown (4)
          .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)
      Total Length: 330
      Identification: 0x0000 (0)
      Flags: 0x0000
          0... .... .... .... = Reserved bit: Not set
          .0.. .... .... .... = Don't fragment: Not set
          ..0. .... .... .... = More fragments: Not set
          ...0 0000 0000 0000 = Fragment offset: 0
      Time to live: 128
      Protocol: UDP (17)
      Header checksum: 0xafa9 [validation disabled]
      [Header checksum status: Unverified]
      Source: 192.168.4.1
      Destination: 192.168.4.152
  **User Datagram Protocol, Src Port: 67, Dst Port: 68**
      Source Port: 67
      Destination Port: 68
      Length: 310
      Checksum: 0x92db [unverified]
      [Checksum Status: Unverified]
      [Stream index: 1]
  **Bootstrap Protocol (ACK)**
      Message type: Boot Reply (2)
      Hardware type: Ethernet (0x01)
      Hardware address length: 6
      Hops: 0
      **Transaction ID: 0xfd9859a7**
      Seconds elapsed: 0
      Bootp flags: 0x0000 (Unicast)
          0... .... .... .... = Broadcast flag: Unicast
          .000 0000 0000 0000 = Reserved flags: 0x0000
      Client IP address: 0.0.0.0
      **Your (client) IP address: 192.168.4.152**
      Next server IP address: 0.0.0.0
      Relay agent IP address: 0.0.0.0
      **Client MAC address: 3c:58:c2:2f:91:21**
      Client hardware address padding: 00000000000000000000
      Server host name not given
      Boot file name not given
      Magic cookie: DHCP
      **Option: (53) DHCP Message Type (ACK)**
          Length: 1
          **DHCP: ACK (5)**
      Option: (54) DHCP Server Identifier
          Length: 4
          **DHCP Server Identifier: 192.168.4.1**
      Option: (51) IP Address Lease Time
          Length: 4
          IP Address Lease Time: (86400s) 1 day
      Option: (1) Subnet Mask
          Length: 4
          **Subnet Mask: 255.255.255.0**
      Option: (3) Router
          Length: 4
          **Router: 192.168.4.1**
      Option: (6) Domain Name Server
          Length: 4
          **Domain Name Server: 192.168.4.1**
      Option: (15) Domain Name
          Length: 11
          Domain Name: localdomain
      **Option: (119) Domain Search**
          **Length: 13**
          **FQDN: localdomain**
      Option: (255) End
          Option End: 255

This output looks similar to what :program:`tcpdump` reported, except here we
can see the decode for Option 119. It looks like the DHCP server is providing
the FQDN of “localdomain.”

Zeek’s Rendition of DORA
========================

With this background, let’s look at Zeek’s depiction of this DHCP exchange.

::

  {
    "ts": "2020-10-02T04:14:39.135304Z",
    "uids": [
      "COoA8M1gbTowuPlVT",
      "CapFoX32zVg3R6TATc"
    ],
    "client_addr": "192.168.4.152",
    "server_addr": "192.168.4.1",
    "mac": "3c:58:c2:2f:91:21",
    "host_name": "3071N0098017422",
    "client_fqdn": "3071N0098017422.fcps.edu",
    "domain": "localdomain",
    "requested_addr": "192.168.4.152",
    "assigned_addr": "192.168.4.152",
    "lease_time": 86400,
    "msg_types": [
      "DISCOVER",
      "OFFER",
      "REQUEST",
      "ACK"
    ],
    "duration": 0.416348934173584
  }

As you can see, Zeek has taken the important elements from all four DORA
messages and produced a single log entry. Every field is interesting, so I did
not highlight them all.

Two UIDs
========

You might be wondering why there are two UID fields for this single DHCP
exchange. Let’s look at the two corresponding :file:`conn.log` entries.

The first one shows a “conversation” between ``0.0.0.0`` and ``255.255.255.0``.
This represents the DHCP Discover message, caused by a client not knowing its
source IP address, sending its search to the local network for a DHCP server.

.. literal-emph::

  {
    "ts": "2020-10-02T04:14:14.443346Z",
    "uid": "COoA8M1gbTowuPlVT",
    **"id.orig_h": "0.0.0.0",**
    **"id.orig_p": 68,**
    **"id.resp_h": "255.255.255.255",**
    **"id.resp_p": 67,**
    "proto": "udp",
    "service": "dhcp",
    "duration": 63.16645097732544,
    "orig_bytes": 1211,
    "resp_bytes": 0,
    "conn_state": "S0",
    "local_orig": false,
    "local_resp": false,
    "missed_bytes": 0,
    "history": "D",
    **"orig_pkts": 4,**
    "orig_ip_bytes": 1323,
    "resp_pkts": 0,
    "resp_ip_bytes": 0,
    "sensorname": "so16-enp0s8"
  }

Notice that Zeek has tracked 4 “orig packets” here, which does not strictly
correspond to the 2 datagrams from ``0.0.0.0`` to ``255.255.255.255``. Remember
the DORA via :program:`tcpdump` output?

It’s possible Zeek included other packets involving ``0.0.0.0`` and
``255.255.255.255`` when it created this log entry since this is a broadcast
and Zeek generally may trouble with that because it doesn't fit the
"connection" abstraction.

The second message shows a conversation between ``192.168.4.152``, the DHCP
client, and ``192.168.4.1``, the DHCP server.

.. literal-emph::

  {
    "ts": "2020-10-02T04:14:39.120138Z",
    "uid": "CapFoX32zVg3R6TATc",
    **"id.orig_h": "192.168.4.152",**
    **"id.orig_p": 68,**
    **"id.resp_h": "192.168.4.1",**
    **"id.resp_p": 67,**
    "proto": "udp",
    "service": "dhcp",
    "duration": 0.3367769718170166,
    "orig_bytes": 0,
    "resp_bytes": 604,
    "conn_state": "SHR",
    "local_orig": true,
    "local_resp": true,
    "missed_bytes": 0,
    "history": "^d",
    "orig_pkts": 0,
    "orig_ip_bytes": 0,
    "resp_pkts": 2,
    "resp_ip_bytes": 660,
    "sensorname": "so16-enp0s8"
  }

Here the count of 2 ``resp_pkts`` is correct.

Enumerating DHCP Servers
========================

Analysts can use Zeek’s :file:`dhcp.log` to enumerate systems providing DHCP
services. Consider the output of the following query.

.. code-block:: console

  $ find . -name "dhcp**.gz" | while read -r file; do zcat -f "$file"; done | jq -c '[."server_addr"]' | sort | uniq -c | sort -nr | head -10

::

     1337 [null]
      119 ["192.168.4.1"]

Here we see that ``192.168.4.1`` is providing DHCP services on this network.
The null entries refer to DHCP log entries that do not have a ``server_addr``
field. One example is Zeek’s log for this DHCP Discover message:

.. literal-emph::

  {
    "ts": "2020-10-06T23:59:48.577749Z",
    "uids": [
      "CctZMx18mIK1qj9Vci"
    ],
    "mac": "80:ee:73:52:eb:59",
    "host_name": "ds61",
    "msg_types": [
      **"DISCOVER"**
    ],
    "duration": 0
  }

This log entry does not have a ``server_addr`` field, so the query above returns a null result.

Conclusion
==========

DHCP is crucial to the proper operation of any IP network. DHCP logs help
analysts map IP addresses to MAC addresses, and may also reveal hostnames. When
investigating suspicious or malicious activity, analysts need to know what
system was assigned what IP address, as DHCP leases expire. However, depending
on the network, systems may retain specific IP addresses for a long time as
they may request an old address as was seen in this example. Of course,
administrators who have configured DHCP to provide fixed IP addresses based on
MAC address will ensure that these machines receive the same IP address,
despite relying on the “dynamic” nature of DHCP.
