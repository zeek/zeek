:tocdepth: 3

base/frameworks/cluster/publish-on-change.zeek
==============================================
.. zeek:namespace:: Cluster

Supporting script code for the &publish_on_change attribute.

:Namespace: Cluster
:Imports: :doc:`base/bif/publish_on_change.bif.zeek </scripts/base/bif/publish_on_change.bif.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
============================================================================================ =====================================================================
:zeek:id:`Cluster::default_publish_table_batch_size`: :zeek:type:`count` :zeek:attr:`&redef` Default number of :zeek:see:`Cluster::TableChangeInfo` records to use
                                                                                             with :zeek:see:`Cluster::publish_table`.
============================================================================================ =====================================================================

Functions
#########
======================================================== ==================================================================================
:zeek:id:`Cluster::publish_table`: :zeek:type:`function` Publish the given table_val using multiple :zeek:see:`Cluster::table_change_infos`
                                                         event to the given topic.
======================================================== ==================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Cluster::default_publish_table_batch_size
   :source-code: base/frameworks/cluster/publish-on-change.zeek 9 9

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10000``

   Default number of :zeek:see:`Cluster::TableChangeInfo` records to use
   with :zeek:see:`Cluster::publish_table`.

Functions
#########
.. zeek:id:: Cluster::publish_table
   :source-code: base/frameworks/cluster/publish-on-change.zeek 29 32

   :Type: :zeek:type:`function` (topic: :zeek:type:`string`, table_val: :zeek:type:`any`, batch_size: :zeek:type:`count` :zeek:attr:`&default` = :zeek:see:`Cluster::default_publish_table_batch_size` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Publish the given table_val using multiple :zeek:see:`Cluster::table_change_infos`
   event to the given topic.


   :param topic: The topic to publish the :zeek:see:`Cluster::table_change_infos` event to.
          Usually this is created with :zeek:see:`Cluster::node_topic` or
          :zeek:see:`Cluster::nodeid_topic`.

   :param table_val: The table to publish. Must have a :zeek:attr:`&publish_on_change` attribute.

   :param batch_size: Number of :zeek:see:`Cluster::TableChangeInfo` records to use per event.


