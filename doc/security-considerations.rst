
.. _security-considerations:

=========================
 Security Considerations
=========================

When running Zeek, you should be aware of the security implications involved,
and consider available options to protect your systems from harm.

Zeek is a complex application. As a network monitor, it processes fundamentally
untrusted input in every packet it inspects, regardless of whether that's live
traffic or recorded into a pcap file. By transmitting carefully crafted packets,
attackers can try to evade Zeek's analysis, or---worse---try to exploit Zeek's
protocol parsers for nefarious purposes.

A Zeek cluster consists of a set of communicating system processes, possibly on
multiple machines (we'll say more about this :ref:`later
<devel-cluster-architectures>`), so as a distributed system Zeek faces
additional threats from eavesdropping, denial of service, and untrusted
input. The cluster's internal communication is structured around messages sent
by `publishing` to various `topics` and received by `subscribing` to such
topics. That is, all members of the cluster communicate as equals. Add to this
the fact that Zeek often runs as root, and caution is clearly warranted.

Hardening your setup against these threats is an advanced topic, and you don't
need to figure out all of this right away. For now, just keep in mind that Zeek
is security-critical infrastructure and you'll need to treat it as such.

Protective Measures
===================

The following lists steps you can take to protect your Zeek cluster.

* Isolate your Zeek cluster from the outside world. On physical networks, place
  Zeek in a dedicated, access-controlled management network, firewalled from
  production networks. In containerized or virtual networks, apply similar
  isolation primitives. Double-check external port reachability.

* Configure encrypted cluster communication to protect against message
  eavesdropping and to authenticate endpoints, particularly if you run a
  multi-machine cluster. Starting with Zeek 8.2., the :ref:`ZeroMQ cluster
  backend <cluster_backend_zeromq>` can automatically configure encryption in
  such settings. The :ref:`Broker cluster backend <broker-framework>` uses
  unauthenticated encryption by default to protect against eavesdropping, but
  you can provide additional credentials to authenticate the nodes. See `here
  <https://github.com/zeek/zeek/blob/master/testing/btest/broker/remote_event_ssl_auth.zeek>`_
  for an example.

* On Linux, consider the ``CAP_NET_RAW`` and ``CAP_NET_ADMIN`` capabilities to
  avoid the need to run Zeek as root. You can `extend zeekctl to support this
  <https://github.com/userjack6880/zeekctl-setcap/tree/master>`_, or use
  systemd's `built-in capabilities management
  <https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#AmbientCapabilities=>`_
  to apply them.
