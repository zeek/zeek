.. _conn-handling:

===================
Connection Handling
===================

Flipping Connections
====================

Zeek works with a concept of originator and responder for a connection. This
is visible in the Zeek scripting layer as the ``is_orig: bool`` event parameter,
but also on much lower-level C++ APIs like the various Analyzer APIs or accessors
on ``Connection`` instances (``OrigAddr()`` and ``RespAddr(), or ``OrigPort()``
and ``RespPort()``).

In certain scenarios, Zeek decides to flip the notion of originator and responder.
Usually, the first packet of a connection determines which endpoint is the originator
and which the responder. As a special case, when the first packet has a source port
that is set in :zeek:see:`likely_server_ports`, this notion is flipped and a ``^``
(caret) added to this connection's history.

This connection flipping permeates various layers. For example, there is a
:zeek:see:`connection_flipped` event that allows Zeek scripts to react on it.
Additionally, the Analyzer API offers a virtual ``FlipRoles()`` method that
is executed recursively on the analyzer tree when endpoint flipping happens.
All analyzers have to update their internal state upon such an event.
Consider the ``ConnSize_Analyzer`` analyzer: It tracks packet and byte counts
transferred by originator and responder endpoints. When the notion of these
endpoints changes, a ``ConnSize_Analyzer`` instance needs to update its own
internal state, as for any following ``DeliverPacket()`` calls, the meaning
of ``is_orig`` is inverted.

Luckily, this flipping usually happens before the first packet of connection
is processed. More recently, however, flipping on
`the second packet <https://github.com/zeek/zeek/pull/2191>`_ has been added.
Technically, flipping can be triggered by any analyzer or logic at any time,
but this results in the very unfortunate scenario that an in-flight ``ForwardStream()`` or
``ForwardPacket()`` invocation on a connection's analyzer tree ends-up using a
stale ``is_orig`` parameter. For example, this was observed with the ``ConnSize_Analyzer``
that is visited after a ``TCPSessionAdapter::Process()`` invocation. If ``Process()``
flipped the connection, the ``DeliverPacket()`` invocation on the ``ConnSize_Analyzer``
would use a stale ``is_orig`` stack variable resulting in miss-accounting
single packets.

In the future, it might make sense to re-design Zeek's lowest layers to be agnostic of
the originator and responder notion. That is, always sort endpoints deterministically
and name them, e.g., ``left`` and ``right``. The notion of originator and responder
shouldn't vanish from Zeek, but instead implemented on a higher-level instead.
For example, the ``IPBasedConnKey`` class currently holds a ``flipped`` member and
has a ``FlipRoles()`` API.
However, it seems unreasonable that the raw connection tracking layer should
have knowledge of the originator and responder concept, as it introduces quite
some complexity.
