:tocdepth: 3

base/bif/publish_on_change.bif.zeek
===================================
.. zeek:namespace:: Cluster
.. zeek:namespace:: GLOBAL


:Namespaces: Cluster, GLOBAL

Summary
~~~~~~~
Functions
#########
=============================================================================== =
:zeek:id:`Cluster::apply_table_change_infos`: :zeek:type:`function`
:zeek:id:`Cluster::set_forward_table_change_infos_topic`: :zeek:type:`function`
=============================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Cluster::apply_table_change_infos
   :source-code: base/bif/publish_on_change.bif.zeek 16 16

   :Type: :zeek:type:`function` (tcheader: :zeek:type:`Cluster::TableChangeHeader`, table_change_infos: :zeek:type:`Cluster::TableChangeInfos`) : :zeek:type:`bool`


.. zeek:id:: Cluster::set_forward_table_change_infos_topic
   :source-code: base/bif/publish_on_change.bif.zeek 13 13

   :Type: :zeek:type:`function` (topic: :zeek:type:`string`) : :zeek:type:`void`



