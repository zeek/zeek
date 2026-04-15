:tocdepth: 3

base/bif/plugins/Zeek_Cluster_Backend_ZeroMQ.cluster_backend_zeromq.bif.zeek
============================================================================
.. zeek:namespace:: Cluster::Backend::ZeroMQ
.. zeek:namespace:: GLOBAL


:Namespaces: Cluster::Backend::ZeroMQ, GLOBAL

Summary
~~~~~~~
Functions
#########
================================================================================== ========================
:zeek:id:`Cluster::Backend::ZeroMQ::generate_keypair`: :zeek:type:`function`       Generate a CURVE keypair
:zeek:id:`Cluster::Backend::ZeroMQ::spawn_zmq_proxy_thread`: :zeek:type:`function`
================================================================================== ========================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Cluster::Backend::ZeroMQ::generate_keypair
   :source-code: base/bif/plugins/Zeek_Cluster_Backend_ZeroMQ.cluster_backend_zeromq.bif.zeek 15 15

   :Type: :zeek:type:`function` () : :zeek:type:`table_string_of_string`

   Generate a CURVE keypair


   :returns: A table[string] of string with keys "public" and "secret".

.. zeek:id:: Cluster::Backend::ZeroMQ::spawn_zmq_proxy_thread
   :source-code: base/bif/plugins/Zeek_Cluster_Backend_ZeroMQ.cluster_backend_zeromq.bif.zeek 9 9

   :Type: :zeek:type:`function` () : :zeek:type:`bool`



