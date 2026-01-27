==============
traceroute.log
==============

Traceroute is a network diagnostic method by which a system can try to
determine the intermediate routing devices between it and a remote system.
Implementations exist for all operating systems. The method generally relies on
sending Internet Control Message Protocol (ICMP) messages or User Datagram
Protocol (UDP) datagrams with incrementing Internet Protocol (IP) time to live
(TTL) values. Some custom implementations use TCP, as it is the IP TTL value
which is the key to the method. For more on how traceroute works, please
consult a networking book.

Zeek ships with a script that tries to identify traceroute activity. The script
tracks ICMP time exceeded messages indicating low TTL values.

For full details on each field in the :file:`traceroute.log` file, please refer
to :zeek:see:`Traceroute::Info`.

:file:`traceroute.log`
======================

The :file:`traceroute.log` only contains four fields. Here is an example
excerpt:

.. literal-emph::

  {"ts":"2020-12-07T05:14:54.202099Z","src":"192.168.4.48","dst":"213.133.109.134",**"proto":"udp"**}
  {"ts":"2020-12-07T05:14:54.367071Z","src":"192.168.4.48","dst":"131.72.76.118",**"proto":"icmp"**}
  {"ts":"2020-12-07T05:25:13.222095Z","src":"192.168.4.48","dst":"216.113.20.1","proto":"udp"}
  {"ts":"2020-12-07T05:30:58.502092Z","src":"192.168.4.48","dst":"193.0.14.129","proto":"udp"}

Beyond the timestamp, source IP address, and destination IP address, the only
remaining field is the protocol, ``proto``. This field indicates the protocol
that was used by the :program:`traceroute` program. In the second entry,
:program:`traceroute` used ICMP. In the other three cases,
:program:`traceroute` used UDP.

Conclusion
==========

The :file:`traceroute.log` may not be enabled by default on your Zeek
installation. It is useful if you want to identify systems using the method to
try to enumerate routing devices between the initiator and the target.
