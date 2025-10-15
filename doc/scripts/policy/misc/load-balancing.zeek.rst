:tocdepth: 3

policy/misc/load-balancing.zeek
===============================
.. zeek:namespace:: LoadBalancing

This script implements the "Zeek side" of several load balancing
approaches for Zeek clusters.

:Namespace: LoadBalancing
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/frameworks/packet-filter </scripts/base/frameworks/packet-filter/index>`

Summary
~~~~~~~
Redefinable Options
###################
======================================================================================== ============================================
:zeek:id:`LoadBalancing::method`: :zeek:type:`LoadBalancing::Method` :zeek:attr:`&redef` Defines the method of load balancing to use.
======================================================================================== ============================================

Types
#####
===================================================== =
:zeek:type:`LoadBalancing::Method`: :zeek:type:`enum` 
===================================================== =

Redefinitions
#############
=============================================== ===============================================================
:zeek:type:`Cluster::Node`: :zeek:type:`record` 
                                                
                                                :New Fields: :zeek:type:`Cluster::Node`
                                                
                                                  lb_filter: :zeek:type:`string` :zeek:attr:`&optional`
                                                    A BPF filter for load balancing traffic sniffed on a single
                                                    interface across a number of processes.
=============================================== ===============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: LoadBalancing::method
   :source-code: policy/misc/load-balancing.zeek 22 22

   :Type: :zeek:type:`LoadBalancing::Method`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``LoadBalancing::AUTO_BPF``

   Defines the method of load balancing to use.

Types
#####
.. zeek:type:: LoadBalancing::Method
   :source-code: policy/misc/load-balancing.zeek 15 20

   :Type: :zeek:type:`enum`

      .. zeek:enum:: LoadBalancing::AUTO_BPF LoadBalancing::Method

         Apply BPF filters to each worker in a way that causes them to
         automatically flow balance traffic between them.



