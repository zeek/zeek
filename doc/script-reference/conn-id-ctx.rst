
.. _script-conn-id-ctx:

==============================
Use of :zeek:see:`conn_id_ctx`
==============================

.. versionadded:: 8.0

.. note::

   We’re still iterating on patterns for working with the new pluggable
   connection keys and :zeek:see:`conn_id_ctx` instances.
   If you have feedback or run into limitations for your use-cases, please reach out!

In some deployments, Zeek receives traffic from different network
segments that share overlapping IP ranges.
Such settings usually provide some additional means of separating
the ranges, such as VLAN numbers.
For example, host 10.0.0.37 in VLAN 1 and host 10.0.0.37 in VLAN 2 may share
the same IP address, but represent different systems.
In Zeek's terminology, such IP addresses (or their connections) occur in different
*contexts*. In this case the context is the VLAN ID; in other settings,
the context could be, say, Virtual Network Identifiers (VNIs) as used with
UDP-based tunnels like VXLAN or Geneve.
From Zeek's perspective, the context can be any kind of value that
it can derive from packet data.

Since version 8.0, Zeek can extract these contexts through
:ref:`plugin-provided connection key implementations <connkey-plugin>`
and include them into its core connection tracking. Such plugins will normally also
:zeek:keyword:`redefine <redef>` :zeek:see:`conn_id_ctx` with additional
fields to expose this context to the Zeek scripting layer.
For example, loading :doc:`/scripts/policy/frameworks/conn_key/vlan_fivetuple.zeek`
adds :zeek:field:`vlan` and :zeek:field:`inner_vlan` fields to :zeek:see:`conn_id_ctx`.

Script writers can use the :zeek:field:`conn_id$ctx <conn_id$ctx>` field to
distinguish :zeek:type:`addr` values observed in different contexts.
For example, to count the number of connections per originator address in
a context-aware manner, add the :zeek:see:`conn_id_ctx` to the table index:

.. code-block:: zeek

	global connection_counts: table[conn_id_ctx, addr] of count &default=0;

	event new_connection(c: connection)
	    {
	    ++connection_counts[c$id$ctx, c$id$orig_h];
	    }


If, for example, :zeek:field:`ctx` is populated with fields for VLAN tags,
that table will create individual entries per ``(VLAN, addr)`` pair.
This will also work correctly if no context has been defined: ``c$id$ctx`` will
be an empty record with no fields.

Alternatively, users can define their own record type that includes both :zeek:see:`conn_id_ctx` and :zeek:type:`addr`,
and use instances of such records to index into tables:

.. literalinclude:: conn_id_ctx_my_endpoint.zeek
   :caption: conn_id_ctx_my_endpoint.zeek
   :language: zeek
   :linenos:
   :tab-width: 4

This example tracks services that an originator IP address has been observed to interact with.
When loading the :doc:`/scripts/policy/frameworks/conn_key/vlan_fivetuple.zeek`
script, IP addresses in different VLANs are tracked separately:

.. code-block:: shell

    $ zeek -r vlan-collisions.pcap frameworks/conn_key/vlan_fivetuple conn_id_ctx_my_endpoint.zeek
    [ctx=[vlan=42, inner_vlan=<uninitialized>], a=141.142.228.5], HTTP
    [ctx=[vlan=10, inner_vlan=20], a=141.142.228.5], HTTP
    [ctx=[vlan=<uninitialized>, inner_vlan=<uninitialized>], a=141.142.228.5], HTTP


Note that while this script isn't VLAN-specific, it is VLAN-aware. When
using a different connection key plugin like the one discussed in the
:ref:`connection key tutorial <connkey-plugin>`, the result becomes the following,
discriminating entries in the ``talks_with_service`` table by the value of
``c$id$ctx$vxlan_vni``:

.. code-block:: shell

    $ zeek -C -r vxlan-overlapping-http-get.pcap  ConnKey::factory=ConnKey::CONNKEY_VXLAN_VNI_FIVETUPLE conn_id_ctx_my_endpoint.zeek
    [ctx=[vxlan_vni=<uninitialized>], a=141.142.228.5], HTTP
    [ctx=[vxlan_vni=<uninitialized>], a=127.0.0.1], VXLAN
    [ctx=[vxlan_vni=4711], a=141.142.228.5], HTTP
    [ctx=[vxlan_vni=4242], a=141.142.228.5], HTTP


When using Zeek's default five-tuple connection key, the :zeek:see:`conn_id_ctx`
record is empty and originator address 141.142.228.5 appears as a single entry
in the table instead:

.. code-block:: shell

    $ zeek -C -r vxlan-overlapping-http-get.pcap conn_id_ctx_my_endpoint.zeek
    [ctx=[], a=141.142.228.5], HTTP
    [ctx=[], a=127.0.0.1], VXLAN
