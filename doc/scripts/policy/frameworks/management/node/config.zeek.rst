:tocdepth: 3

policy/frameworks/management/node/config.zeek
=============================================
.. zeek:namespace:: Management::Node

Configuration settings for nodes controlled by the Management framework.

:Namespace: Management::Node

Summary
~~~~~~~
Redefinable Options
###################
================================================================================= ======================================
:zeek:id:`Management::Node::node_topic`: :zeek:type:`string` :zeek:attr:`&redef`  The nodes' Broker topic.
:zeek:id:`Management::Node::stderr_file`: :zeek:type:`string` :zeek:attr:`&redef` Cluster node stderr log configuration.
:zeek:id:`Management::Node::stdout_file`: :zeek:type:`string` :zeek:attr:`&redef` Cluster node stdout log configuration.
================================================================================= ======================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Management::Node::node_topic
   :source-code: policy/frameworks/management/node/config.zeek 8 8

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/management/node"``

   The nodes' Broker topic. Cluster nodes automatically subscribe
   to it, to receive request events from the Management framework.

.. zeek:id:: Management::Node::stderr_file
   :source-code: policy/frameworks/management/node/config.zeek 21 21

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"stderr"``

   Cluster node stderr log configuration. Like
   :zeek:see:`Management::Node::stdout_file`, but for the stderr stream.

.. zeek:id:: Management::Node::stdout_file
   :source-code: policy/frameworks/management/node/config.zeek 17 17

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"stdout"``

   Cluster node stdout log configuration. If the string is non-empty,
   Zeek will produce a free-form log (i.e., not one governed by Zeek's
   logging framework) in the node's working directory. If left empty, no
   such log results.
   
   Note that cluster nodes also establish a "proper" management log via
   the :zeek:see:`Management::Log` module.


