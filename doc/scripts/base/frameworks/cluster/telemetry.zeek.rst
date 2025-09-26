:tocdepth: 3

base/frameworks/cluster/telemetry.zeek
======================================
.. zeek:namespace:: Cluster::Telemetry


:Namespace: Cluster::Telemetry

Summary
~~~~~~~
Redefinable Options
###################
================================================================================================================= =================================================================
:zeek:id:`Cluster::Telemetry::core_metrics`: :zeek:type:`set` :zeek:attr:`&redef`                                 The telemetry types to enable for the core backend.
:zeek:id:`Cluster::Telemetry::message_size_bounds`: :zeek:type:`vector` :zeek:attr:`&redef`                       For the DEBUG metrics, the histogram buckets to use.
:zeek:id:`Cluster::Telemetry::topic_normalizations`: :zeek:type:`table` :zeek:attr:`&ordered` :zeek:attr:`&redef` Table used for normalizing topic names that contain random parts.
:zeek:id:`Cluster::Telemetry::websocket_metrics`: :zeek:type:`set` :zeek:attr:`&redef`                            The telemetry types to enable for WebSocket backends.
================================================================================================================= =================================================================

Types
#####
======================================================== =============================
:zeek:type:`Cluster::Telemetry::Type`: :zeek:type:`enum` Module for cluster telemetry.
======================================================== =============================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Cluster::Telemetry::core_metrics
   :source-code: base/frameworks/cluster/telemetry.zeek 19 19

   :Type: :zeek:type:`set` [:zeek:type:`Cluster::Telemetry::Type`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            Cluster::Telemetry::INFO
         }


   The telemetry types to enable for the core backend.

.. zeek:id:: Cluster::Telemetry::message_size_bounds
   :source-code: base/frameworks/cluster/telemetry.zeek 36 36

   :Type: :zeek:type:`vector` of :zeek:type:`double`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         [10.0, 50.0, 100.0, 500.0, 1000.0, 5000.0, 10000.0, 50000.0]


   For the DEBUG metrics, the histogram buckets to use.

.. zeek:id:: Cluster::Telemetry::topic_normalizations
   :source-code: base/frameworks/cluster/telemetry.zeek 31 31

   :Type: :zeek:type:`table` [:zeek:type:`pattern`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&ordered` :zeek:attr:`&redef`
   :Default:

      ::

         {
            [/^?(^zeek\/cluster\/nodeid\/.*)$?/] = "zeek/cluster/nodeid/__normalized__"
         }

   :Redefinition: from :doc:`/scripts/policy/frameworks/cluster/backend/zeromq/main.zeek`

      ``+=``::

         /^?(^zeek\.cluster\.nodeid\..*)$?/ = zeek.cluster.nodeid.__normalized__


   Table used for normalizing topic names that contain random parts.
   Map to an empty string to skip recording a specific metric
   completely.

.. zeek:id:: Cluster::Telemetry::websocket_metrics
   :source-code: base/frameworks/cluster/telemetry.zeek 24 24

   :Type: :zeek:type:`set` [:zeek:type:`Cluster::Telemetry::Type`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            Cluster::Telemetry::INFO
         }


   The telemetry types to enable for WebSocket backends.

Types
#####
.. zeek:type:: Cluster::Telemetry::Type
   :source-code: base/frameworks/cluster/telemetry.zeek 5 17

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Cluster::Telemetry::INFO Cluster::Telemetry::Type

         Creates counter metrics for incoming and for outgoing
         events without labels.

      .. zeek:enum:: Cluster::Telemetry::VERBOSE Cluster::Telemetry::Type

         Creates counter metrics for incoming and outgoing events
         labeled with handler and normalized topic names.

      .. zeek:enum:: Cluster::Telemetry::DEBUG Cluster::Telemetry::Type

         Creates histogram metrics using the serialized message size
         for events, labeled by topic, handler and script location
         (outgoing only).

   Module for cluster telemetry.


