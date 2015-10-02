
.. _brokercomm-framework:

======================================
Broker-Enabled Communication Framework
======================================

.. rst-class:: opening

    Bro can now use the `Broker Library
    <../components/broker/README.html>`_ to exchange information with
    other Bro processes.

.. contents::

Connecting to Peers
===================

Communication via Broker must first be turned on via
:bro:see:`BrokerComm::enable`.

Bro can accept incoming connections by calling :bro:see:`BrokerComm::listen`
and then monitor connection status updates via the
:bro:see:`BrokerComm::incoming_connection_established` and
:bro:see:`BrokerComm::incoming_connection_broken` events.

.. btest-include:: ${DOC_ROOT}/frameworks/broker/connecting-listener.bro

Bro can initiate outgoing connections by calling :bro:see:`BrokerComm::connect`
and then monitor connection status updates via the
:bro:see:`BrokerComm::outgoing_connection_established`,
:bro:see:`BrokerComm::outgoing_connection_broken`, and
:bro:see:`BrokerComm::outgoing_connection_incompatible` events.

.. btest-include:: ${DOC_ROOT}/frameworks/broker/connecting-connector.bro

Remote Printing
===============

To receive remote print messages, first use the
:bro:see:`BrokerComm::subscribe_to_prints` function to advertise to peers a
topic prefix of interest and then create an event handler for
:bro:see:`BrokerComm::print_handler` to handle any print messages that are
received.

.. btest-include:: ${DOC_ROOT}/frameworks/broker/printing-listener.bro

To send remote print messages, just call :bro:see:`BrokerComm::print`.

.. btest-include:: ${DOC_ROOT}/frameworks/broker/printing-connector.bro

Notice that the subscriber only used the prefix "bro/print/", but is
able to receive messages with full topics of "bro/print/hi",
"bro/print/stuff", and "bro/print/bye".  The model here is that the
publisher of a message checks for all subscribers who advertised
interest in a prefix of that message's topic and sends it to them.

Message Format
--------------

For other applications that want to exchange print messages with Bro,
the Broker message format is simply:

.. code:: c++

    broker::message{std::string{}};

Remote Events
=============

Receiving remote events is similar to remote prints.  Just use the
:bro:see:`BrokerComm::subscribe_to_events` function and possibly define any
new events along with handlers that peers may want to send.

.. btest-include:: ${DOC_ROOT}/frameworks/broker/events-listener.bro

There are two different ways to send events.  The first is to call the
:bro:see:`BrokerComm::event` function directly.  The second option is to call
the :bro:see:`BrokerComm::auto_event` function where you specify a
particular event that will be automatically sent to peers whenever the
event is called locally via the normal event invocation syntax.

.. btest-include:: ${DOC_ROOT}/frameworks/broker/events-connector.bro

Again, the subscription model is prefix-based.

Message Format
--------------

For other applications that want to exchange event messages with Bro,
the Broker message format is:

.. code:: c++

    broker::message{std::string{}, ...};

The first parameter is the name of the event and the remaining ``...``
are its arguments, which are any of the supported Broker data types as
they correspond to the Bro types for the event named in the first
parameter of the message.

Remote Logging
==============

.. btest-include:: ${DOC_ROOT}/frameworks/broker/testlog.bro

Use the :bro:see:`BrokerComm::subscribe_to_logs` function to advertise interest
in logs written by peers.  The topic names that Bro uses are implicitly of the
form "bro/log/<stream-name>".

.. btest-include:: ${DOC_ROOT}/frameworks/broker/logs-listener.bro

To send remote logs either redef :bro:see:`Log::enable_remote_logging` or
use the :bro:see:`BrokerComm::enable_remote_logs` function.  The former
allows any log stream to be sent to peers while the latter enables remote
logging for particular streams.

.. btest-include:: ${DOC_ROOT}/frameworks/broker/logs-connector.bro

Message Format
--------------

For other applications that want to exchange log messages with Bro,
the Broker message format is:

.. code:: c++

    broker::message{broker::enum_value{}, broker::record{}};

The enum value corresponds to the stream's :bro:see:`Log::ID` value, and
the record corresponds to a single entry of that log's columns record,
in this case a ``Test::Info`` value.

Tuning Access Control
=====================

By default, endpoints do not restrict the message topics that it sends
to peers and do not restrict what message topics and data store
identifiers get advertised to peers.  These are the default
:bro:see:`BrokerComm::EndpointFlags` supplied to :bro:see:`BrokerComm::enable`.

If not using the ``auto_publish`` flag, one can use the
:bro:see:`BrokerComm::publish_topic` and :bro:see:`BrokerComm::unpublish_topic`
functions to manipulate the set of message topics (must match exactly)
that are allowed to be sent to peer endpoints.  These settings take
precedence over the per-message ``peers`` flag supplied to functions
that take a :bro:see:`BrokerComm::SendFlags` such as :bro:see:`BrokerComm::print`,
:bro:see:`BrokerComm::event`, :bro:see:`BrokerComm::auto_event` or
:bro:see:`BrokerComm::enable_remote_logs`.

If not using the ``auto_advertise`` flag, one can use the
:bro:see:`BrokerComm::advertise_topic` and
:bro:see:`BrokerComm::unadvertise_topic` functions
to manipulate the set of topic prefixes that are allowed to be
advertised to peers.  If an endpoint does not advertise a topic prefix, then
the only way peers can send messages to it is via the ``unsolicited``
flag of :bro:see:`BrokerComm::SendFlags` and choosing a topic with a matching
prefix (i.e. full topic may be longer than receivers prefix, just the
prefix needs to match).

Distributed Data Stores
=======================

There are three flavors of key-value data store interfaces: master,
clone, and frontend.

A frontend is the common interface to query and modify data stores.
That is, a clone is a specific type of frontend and a master is also a
specific type of frontend, but a standalone frontend can also exist to
e.g. query and modify the contents of a remote master store without
actually "owning" any of the contents itself.

A master data store can be cloned from remote peers which may then
perform lightweight, local queries against the clone, which
automatically stays synchronized with the master store.  Clones cannot
modify their content directly, instead they send modifications to the
centralized master store which applies them and then broadcasts them to
all clones.

Master and clone stores get to choose what type of storage backend to
use.  E.g. In-memory versus SQLite for persistence.  Note that if clones
are used, then data store sizes must be able to fit within memory
regardless of the storage backend as a single snapshot of the master
store is sent in a single chunk to initialize the clone.

Data stores also support expiration on a per-key basis either using an
absolute point in time or a relative amount of time since the entry's
last modification time.

.. btest-include:: ${DOC_ROOT}/frameworks/broker/stores-listener.bro

.. btest-include:: ${DOC_ROOT}/frameworks/broker/stores-connector.bro

In the above example, if a local copy of the store contents isn't
needed, just replace the :bro:see:`BrokerStore::create_clone` call with
:bro:see:`BrokerStore::create_frontend`.  Queries will then be made against
the remote master store instead of the local clone.

Note that all data store queries must be made within Bro's asynchronous
``when`` statements and must specify a timeout block.
