:tocdepth: 3

policy/misc/load-balancing.zeek
===============================
.. bro:namespace:: LoadBalancing

This script implements the "Bro side" of several load balancing
approaches for Bro clusters.

:Namespace: LoadBalancing
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/frameworks/packet-filter </scripts/base/frameworks/packet-filter/index>`

Summary
~~~~~~~
Redefinable Options
###################
===================================================================================== ============================================
:bro:id:`LoadBalancing::method`: :bro:type:`LoadBalancing::Method` :bro:attr:`&redef` Defines the method of load balancing to use.
===================================================================================== ============================================

Types
#####
=================================================== =
:bro:type:`LoadBalancing::Method`: :bro:type:`enum` 
=================================================== =

Redefinitions
#############
============================================= =
:bro:type:`Cluster::Node`: :bro:type:`record` 
============================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: LoadBalancing::method

   :Type: :bro:type:`LoadBalancing::Method`
   :Attributes: :bro:attr:`&redef`
   :Default: ``LoadBalancing::AUTO_BPF``

   Defines the method of load balancing to use.

Types
#####
.. bro:type:: LoadBalancing::Method

   :Type: :bro:type:`enum`

      .. bro:enum:: LoadBalancing::AUTO_BPF LoadBalancing::Method

         Apply BPF filters to each worker in a way that causes them to
         automatically flow balance traffic between them.



