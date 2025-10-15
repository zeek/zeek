:tocdepth: 3

policy/frameworks/management/node/main.zeek
===========================================
.. zeek:namespace:: Management::Node

This module provides Management framework functionality present in every
cluster node, to allowing Management agents to interact with the nodes.

:Namespace: Management::Node
:Imports: :doc:`base/frameworks/broker/store.zeek </scripts/base/frameworks/broker/store.zeek>`, :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/frameworks/logging/writers/ascii.zeek </scripts/base/frameworks/logging/writers/ascii.zeek>`, :doc:`base/misc/installation.zeek </scripts/base/misc/installation.zeek>`, :doc:`base/utils/paths.zeek </scripts/base/utils/paths.zeek>`, :doc:`policy/frameworks/management </scripts/policy/frameworks/management/index>`, :doc:`policy/frameworks/management/agent/config.zeek </scripts/policy/frameworks/management/agent/config.zeek>`, :doc:`policy/frameworks/management/node/api.zeek </scripts/policy/frameworks/management/node/api.zeek>`, :doc:`policy/frameworks/management/node/config.zeek </scripts/policy/frameworks/management/node/config.zeek>`

Summary
~~~~~~~
Redefinitions
#############
============================================================================== =
:zeek:id:`Management::role`: :zeek:type:`Management::Role` :zeek:attr:`&redef` 
============================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~

