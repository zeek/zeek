:tocdepth: 3

base/bif/supervisor.bif.zeek
============================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: Supervisor

The BIFs that define the Zeek supervisor control interface.

:Namespaces: GLOBAL, Supervisor

Summary
~~~~~~~
Functions
#########
============================================================= =
:zeek:id:`Supervisor::__create`: :zeek:type:`function`        
:zeek:id:`Supervisor::__destroy`: :zeek:type:`function`       
:zeek:id:`Supervisor::__init_cluster`: :zeek:type:`function`  
:zeek:id:`Supervisor::__is_supervised`: :zeek:type:`function` 
:zeek:id:`Supervisor::__is_supervisor`: :zeek:type:`function` 
:zeek:id:`Supervisor::__node`: :zeek:type:`function`          
:zeek:id:`Supervisor::__restart`: :zeek:type:`function`       
:zeek:id:`Supervisor::__status`: :zeek:type:`function`        
============================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Supervisor::__create

   :Type: :zeek:type:`function` (node: :zeek:type:`Supervisor::NodeConfig`) : :zeek:type:`string`


.. zeek:id:: Supervisor::__destroy

   :Type: :zeek:type:`function` (node: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: Supervisor::__init_cluster

   :Type: :zeek:type:`function` () : :zeek:type:`bool`


.. zeek:id:: Supervisor::__is_supervised

   :Type: :zeek:type:`function` () : :zeek:type:`bool`


.. zeek:id:: Supervisor::__is_supervisor

   :Type: :zeek:type:`function` () : :zeek:type:`bool`


.. zeek:id:: Supervisor::__node

   :Type: :zeek:type:`function` () : :zeek:type:`Supervisor::NodeConfig`


.. zeek:id:: Supervisor::__restart

   :Type: :zeek:type:`function` (node: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: Supervisor::__status

   :Type: :zeek:type:`function` (node: :zeek:type:`string`) : :zeek:type:`Supervisor::Status`



