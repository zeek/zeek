.. _connkey-plugin:

===============================
Writing a Connection Key Plugin
===============================

.. versionadded:: 8.0

By default, Zeek looks up internal connection state using the classic five-tuple
of originator and responder IP addresses, ports, and the numeric protocol
identifier (for TCP, UDP, etc). Zeek's data structure driving this is called a
connection key, or ``ConnKey``.

In certain environments the classic five-tuple does not sufficiently distinguish
connections. Consider traffic mirrored from multiple VLANs with overlapping IP
address ranges. Concretely, a connection between 10.0.0.1 and 10.0.0.2 in one
VLAN is distinct from a connection between the same IPs in another VLAN.  Here,
Zeek should include the VLAN identifier into the connection key, and you can
instruct Zeek to do so by loading the
:doc:`/scripts/policy/frameworks/conn_key/vlan_fivetuple.zeek` policy script.

Zeek's plugin API allows adding support for additional custom connection keys.
This section provides a tutorial on how to do so, using the example of VXLAN-enabled
flow tuples. If you're not familiar with plugin development, head over to the
:ref:`Writing Plugins <writing-plugins>` section.

Our goal is to implement a custom connection key to scope connections
transported within a `VXLAN <https://datatracker.ietf.org/doc/html/rfc7348/index.html>`_
tunnel by the VXLAN Network Identifier (VNI).

As a test case, we have encapsulated the `HTTP GET trace <https://github.com/zeek/zeek/raw/refs/heads/master/testing/btest/Traces/http/get.trace>`_
from the Zeek repository twice with VXLAN using VNIs 4711 and 4242, respectively,
and merged the resulting two PCAP files with the original PCAP.
The :download:`resulting PCAP <connkey-vxlan-fivetuple-plugin-src/Traces/vxlan-overlapping-http-get.pcap>`
contains three HTTP connections, two of which are VXLAN-encapsulated.

By default, Zeek will create the same connection key for the original and
encapsulated HTTP connections, since they have identical inner five-tuples.
Therefore, Zeek creates only a single ``http.log`` entry, and two entries
in ``conn.log``.

.. code-block:: shell

    $ zeek -C -r Traces/vxlan-overlapping-http-get.pcap
    $ zeek-cut -m uid method host uri < http.log
    uid     method  host    uri
    CpWF5etn1l2rpaLu3       GET     bro.org /download/CHANGES.bro-aux.txt

    $ zeek-cut -m uid service history orig_pkts resp_pkts < conn.log
    uid     service history orig_pkts       resp_pkts
    Cq2CY245oGGbibJ8k9      http    ShADTadtFf      21      21
    CMleDu4xANIMzePYd7      vxlan   D       28      0

Note that just two of the HTTP connections are encapsulated.
That is why the VXLAN connection shows only 28 packets.
Each HTTP connection has 14 packets total, 7 in each direction. Zeek aggregates
all packets into the single HTTP connection, but only 28 of them were
transported within the VXLAN tunnel connection. Note also the ``t`` and ``T``
flags in the :zeek:field:`Conn::Info$history` field. These stand for retransmissions,
caused by Zeek not discriminating between the different HTTP connections.

The plugin we'll develop below adds the VXLAN VNI to the connection key.
As a result, Zeek will correctly report three HTTP connections, tracked
and logged separately. We'll add the VNI as
:zeek:field:`vxlan_vni` to the :zeek:see:`conn_id_ctx` record, making it available
in ``http.log`` and ``conn.log`` via the ``id.ctx.vxlan_vni`` column.

After activating the plugin Zeek tracks each HTTP connection individually and
the logs will look as follows:

.. code-block:: shell

    $ zeek-cut -m uid method host uri id.ctx.vxlan_vni < http.log
    uid     method  host    uri     id.ctx.vxlan_vni
    CBifsS2vqGEg8Fa5ac      GET     bro.org /download/CHANGES.bro-aux.txt   4711
    CEllEz13txeSrbGqBe      GET     bro.org /download/CHANGES.bro-aux.txt   4242
    CRfbJw1kBBvHDQQBta      GET     bro.org /download/CHANGES.bro-aux.txt   -

    $ zeek-cut -m uid service history orig_pkts resp_pkts id.ctx.vxlan_vni < conn.log
    uid     service history orig_pkts       resp_pkts       id.ctx.vxlan_vni
    CRfbJw1kBBvHDQQBta      http    ShADadFf        7       7       -
    CEllEz13txeSrbGqBe      http    ShADadFf        7       7       4242
    CBifsS2vqGEg8Fa5ac      http    ShADadFf        7       7       4711
    CC6Ald2LejCS1qcDy4      vxlan   D       28      0       -


Implementation
==============

Adding alternative connection keys involves implementing two classes.
First, a factory class producing ``zeek::ConnKey`` instances. This
is the class created through the added ``zeek::conn_key::Component``.
Second, a custom connection key class derived from ``zeek::ConnKey``.
Instances of this class are created by the factory. This is a typical
abstract factory pattern.

Our plugin's ``Configure()`` method follows the standard pattern of setting up
basic information about the plugin and registering our own ``ConnKey`` component.

.. literalinclude:: connkey-vxlan-fivetuple-plugin-src/src/Plugin.cc
   :caption: Plugin.cc
   :language: cpp
   :lines: 16-
   :linenos:
   :tab-width: 4


Next, in the ``Factory.cc`` file, we're implementing a custom ``zeek::ConnKey`` class.
This class is named ``VxlanVniConnKey`` and inherits from ``zeek::IPBasedConnKey``.
While ``zeek::ConnKey`` is technically the base class, in this tutorial we'll
derive from ``zeek::IPBasedConnKey``.
Currently, Zeek only supports IP-based connection tracking via the
``IPBasedAnalyzer`` analyzer. This analyzer requires ``zeek::IPBasedConnKey``
instances.

.. literalinclude:: connkey-vxlan-fivetuple-plugin-src/src/Factory.cc
   :caption: VxlanVniConnKey class in Factory.cc
   :language: cpp
   :linenos:
   :lines: 18-78
   :tab-width: 4

The current pattern for custom connection keys is to embed the bytes used for
the ``zeek::session::detail::Key`` as a packed struct within a ``ConnKey`` instance.
We override ``DoPopulateConnIdVal()`` to set the :zeek:field:`vxlan_vni` field
of the :zeek:see:`conn_id_ctx` record value to the extracted VXLAN VNI. A small trick
employed is that we default the most significant byte of ``key.vxlan_vni`` to 0xFF.
As a VNI has only 24 bits, this allows us to determine if a VNI was actually
extracted, or whether it remained unset.

The ``DoInit()`` implementation is the actual place for connection key customization.
This is where we extract the VXLAN VNI from packet data. To do so, we're using the relatively
new ``GetAnalyzerData()`` API of the packet analysis manager.
This API allows generic access to the raw data layers analyzed by a give packet analyzer.
For our use-case, we take the most outer VXLAN layer, if any, and extract the VNI
into ``key.vxlan_vni``.

There's no requirement to use the ``GetAnalyzerData()`` API. If the ``zeek::Packet``
instance passed to ``DoInit()`` contains the needed information, e.g. VLAN identifiers
or information from the packet's raw bytes, you can use them directly.
Specifically, ``GetAnalyzerData()`` may introduce additional overhead into the
packet path that you can avoid if the information is readily available
elsewhere.
Using other Zeek APIs to determine connection key information is of course
also possible.

The next part shown concerns the ``Factory`` class itself. The
``DoConnKeyFromVal()`` method contains logic to produce a ``VxlanVniConnKey``
instance from an existing :zeek:see:`conn_id` record.
This is needed in order for the :zeek:see:`lookup_connection` builtin function to work properly.
The implementation re-uses the ``DoConnKeyFromVal()`` implementation of the
default ``fivetuple::Factory`` that our factory inherits from to extract the
classic five-tuple information.

.. literalinclude:: connkey-vxlan-fivetuple-plugin-src/src/Factory.cc
   :caption: Factory class in Factory.cc
   :language: cpp
   :linenos:
   :lines: 80-103
   :tab-width: 4

Calling the ``fivetuple::Factory::DoConnKeyFromVal()`` in turn calls our
own factory's ``DoNewConnKey()`` method through virtual dispatch.  Since our
factory overrides this method to always return a ``VxlanVniConnKey`` instance,
the static cast later is safe.

Last, the plugin's ``__load__.zeek`` file is shown. It includes the extension
of the :zeek:see:`conn_id_ctx` identifier by the :zeek:field:`vxlan_vni` field.

.. literalinclude:: connkey-vxlan-fivetuple-plugin-src/scripts/__load__.zeek
   :caption: The conn_id redefinition in __load__.zeek
   :language: zeek
   :linenos:
   :tab-width: 4


Using the custom Connection Key
===============================

After installing the plugin, the new connection key implementation can be
selected by redefining the script-level :zeek:see:`ConnKey::factory` variable.
This can either be done in a separate script, but we do it directly on the
command-line for simplicity. The ``ConnKey::CONNKEY_VXLAN_VNI_FIVETUPLE`` is
registered in Zeek during the plugin's ``AddComponent()`` call during
``Configure()``, where the component has the name ``VXLAN_VNI_FIVETUPLE``.

.. code-block:: shell

    $ zeek -C -r Traces/vxlan-overlapping-http-get.pcap  ConnKey::factory=ConnKey::CONNKEY_VXLAN_VNI_FIVETUPLE


Viewing the ``conn.log`` now shows three separate HTTP connections,
two of which have a ``vxlan_vni`` value set in their logs.


.. code-block:: shell

    $ zeek-cut -m uid service history orig_pkts resp_pkts id.ctx.vxlan_vni < conn.log
    uid     service history orig_pkts       resp_pkts       id.ctx.vxlan_vni
    CRfbJw1kBBvHDQQBta      http    ShADadFf        7       7       -
    CEllEz13txeSrbGqBe      http    ShADadFf        7       7       4242
    CBifsS2vqGEg8Fa5ac      http    ShADadFf        7       7       4711
    CC6Ald2LejCS1qcDy4      vxlan   D       28      0       -

Pretty cool, isn't it?
