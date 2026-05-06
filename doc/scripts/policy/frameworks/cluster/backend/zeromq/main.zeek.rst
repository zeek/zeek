:tocdepth: 3

policy/frameworks/cluster/backend/zeromq/main.zeek
==================================================
.. zeek:namespace:: Cluster::Backend::ZeroMQ

ZeroMQ cluster logic

:Namespace: Cluster::Backend::ZeroMQ
:Imports: :doc:`base/utils/addrs.zeek </scripts/base/utils/addrs.zeek>`, :doc:`policy/frameworks/cluster/backend/zeromq/options.zeek </scripts/policy/frameworks/cluster/backend/zeromq/options.zeek>`

Summary
~~~~~~~
Redefinitions
#############
================================================================================================================= =
:zeek:id:`Cluster::Backend::ZeroMQ::run_proxy_thread`: :zeek:type:`bool` :zeek:attr:`&redef`
:zeek:id:`Cluster::Telemetry::topic_normalizations`: :zeek:type:`table` :zeek:attr:`&ordered` :zeek:attr:`&redef`
:zeek:id:`Cluster::backend`: :zeek:type:`Cluster::BackendTag` :zeek:attr:`&redef`
:zeek:id:`Cluster::logger_pool_spec`: :zeek:type:`Cluster::PoolSpec` :zeek:attr:`&redef`
:zeek:id:`Cluster::logger_topic`: :zeek:type:`string` :zeek:attr:`&redef`
:zeek:id:`Cluster::manager_topic`: :zeek:type:`string` :zeek:attr:`&redef`
:zeek:id:`Cluster::node_id`: :zeek:type:`function` :zeek:attr:`&redef`
:zeek:id:`Cluster::node_topic`: :zeek:type:`function` :zeek:attr:`&redef`
:zeek:id:`Cluster::nodeid_topic`: :zeek:type:`function` :zeek:attr:`&redef`
:zeek:id:`Cluster::proxy_pool_spec`: :zeek:type:`Cluster::PoolSpec` :zeek:attr:`&redef`
:zeek:id:`Cluster::proxy_topic`: :zeek:type:`string` :zeek:attr:`&redef`
:zeek:id:`Cluster::worker_pool_spec`: :zeek:type:`Cluster::PoolSpec` :zeek:attr:`&redef`
:zeek:id:`Cluster::worker_topic`: :zeek:type:`string` :zeek:attr:`&redef`
================================================================================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~

